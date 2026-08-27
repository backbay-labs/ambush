use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use swarm_crypto::{DetachedSignature, Ed25519Signer, sha256_hex};
use swarm_governance::persistence_protocol::*;
use swarm_governance::witness_engine::store::{
    WitnessAdmissionEntryV1, WitnessAdmissionSetV1, WitnessAtomicStore, WitnessBucketAnchorV1,
    WitnessBucketConfigurationV1, WitnessBucketEpochV1, WitnessBucketManifestPhaseV1,
    WitnessBucketManifestV1, WitnessCompressionV1, WitnessDiscardPolicyV1,
    WitnessPersistenceSemanticsV1, WitnessRetentionPolicyV1, WitnessStorageTypeV1,
    WitnessStoreCasResultV1, WitnessStoreDeploymentInputsV1, WitnessStoreErrorV1,
    WitnessStoreProxyFailureCodeV1, WitnessStoreProxyOperationV1, WitnessStoreProxyRequestBodyV1,
    WitnessStoreProxyRequestV1, WitnessStoreProxyResponseBodyV1, WitnessStoreProxyResponseV1,
    WitnessStoreProxyValidatedEntryV1, WitnessStoreReadResultV1, WitnessStoreReadyResultV1,
    WitnessStreamInitializationRecordV1, WitnessStreamInitializationV1,
    in_memory::InMemoryWitnessStore,
};
use swarm_governance::witness_engine::{
    WitnessStoreEnvelopeV1, WitnessStoredPreparedV1, witness_stream_key,
};
use swarm_governance::witness_service::{
    WITNESS_SERVICE_REQUEST_DOMAIN_V1, WitnessAdmissionRecordV1, WitnessPrepareVerificationV1,
    WitnessServiceFailureCodeV1, WitnessServiceOperationV1, WitnessServiceRequestBodyV1,
    WitnessServiceRequestV1, WitnessServiceResponseV1, verify_public_prepare,
};
use swarm_governance_witness::{
    NatsPublicWitnessStoreProxyClient, PublicWitnessDispatchErrorV1, PublicWitnessDispatcher,
    PublicWitnessProxyTransportErrorV1, PublicWitnessServiceConfigV1,
    PublicWitnessStoreProxyClient, StoreProxyService, StoreProxyServiceConfigV1,
    StoreProxyServiceErrorV1, StoreProxyServiceRunner, StoreRoleConnectionV1, dispatcher_mapping,
    private_store_ingress_overload_control, public_witness_ingress_overload_control,
    store_proxy_subjects,
};
use tokio::sync::Notify;

#[derive(Clone, Copy, PartialEq, Eq)]
enum CasMode {
    Apply,
    ApplyThenUnavailable,
    ApplyThenConfirmationSubstitute,
    AckMalformed,
    AckDuplicate,
    AckLower,
    AckWrongKind,
    AckWrongStream,
    AckWrongPreviousRevision,
    AckWrongNewRevision,
    AckWrongDigest,
    AckWrongRequestDigest,
    AckUnknown,
    Conflict,
    ConflictWinner,
    Refuse,
}

#[derive(Clone, Copy)]
enum ReadyMutation {
    None,
    WrongOperation,
    WrongRequestDigest,
    WrongBucketConfiguration,
    WrongManifestDigest,
    WrongManifestPhase,
    WrongManifestEpoch,
    WrongWitnessIdentity,
    WrongWitnessKey,
    MissingStream,
    ExtraStream,
    WrongInitializationDigest,
    WrongSummaryRevision,
    WrongStoreDigest,
    CrossStreamSummaries,
}

struct ProxyState {
    revision: u64,
    envelope: WitnessStoreEnvelopeV1,
    events: Vec<&'static str>,
}

#[derive(Clone)]
struct RecordingProxy {
    calls: Arc<AtomicUsize>,
    cas_attempted: Arc<AtomicUsize>,
    cas_applied: Arc<AtomicUsize>,
    inspect_calls: Arc<AtomicUsize>,
    ready_valid_responses: Arc<AtomicUsize>,
    state: Arc<Mutex<ProxyState>>,
    secondary_state: Arc<Mutex<Option<ProxyState>>>,
    entered: Arc<Notify>,
    release: Arc<Mutex<Option<Arc<Notify>>>>,
    cas_mode: Arc<Mutex<CasMode>>,
    conflict_observed: Arc<Mutex<Option<(u64, WitnessStoreEnvelopeV1)>>>,
    confirmation_observed: Arc<Mutex<Option<WitnessStoreEnvelopeV1>>>,
    ready_manifest: Arc<Mutex<WitnessBucketManifestV1>>,
    ready_mutation: Arc<Mutex<ReadyMutation>>,
    ready_signer: Ed25519Signer,
    foreign_ready_signer: Ed25519Signer,
    expected_admission_digest: String,
    expected_epoch_digest: String,
    expected_anchor_digest: String,
}

impl RecordingProxy {
    fn events(&self) -> Vec<&'static str> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .events
            .clone()
    }

    fn reset_observations(&self) {
        self.calls.store(0, Ordering::SeqCst);
        self.cas_attempted.store(0, Ordering::SeqCst);
        self.cas_applied.store(0, Ordering::SeqCst);
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .events
            .clear();
        if let Some(state) = self
            .secondary_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
        {
            state.events.clear();
        }
    }
}

#[async_trait]
impl PublicWitnessStoreProxyClient for RecordingProxy {
    async fn inspect_ready(
        &self,
        request: WitnessStoreProxyRequestV1,
    ) -> Result<WitnessStoreProxyResponseV1, PublicWitnessProxyTransportErrorV1> {
        request
            .validate_structure()
            .and_then(|_| request.validate_semantics())
            .and_then(|_| request.validate_signature())
            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;
        if !matches!(request.body, WitnessStoreProxyRequestBodyV1::InspectReady) {
            return Err(PublicWitnessProxyTransportErrorV1::Framing);
        }
        self.inspect_calls.fetch_add(1, Ordering::SeqCst);
        if request.admission_digest != self.expected_admission_digest
            || request.bucket_epoch_digest != self.expected_epoch_digest
            || request.bucket_anchor_digest != self.expected_anchor_digest
        {
            return Err(PublicWitnessProxyTransportErrorV1::Framing);
        }
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut manifest = self
            .ready_manifest
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let mut validated_streams = BTreeMap::new();
        validated_streams.insert(
            state.envelope.stream_id.clone(),
            WitnessStoreProxyValidatedEntryV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                revision: state.revision,
                store_state_digest: state
                    .envelope
                    .store_state_digest()
                    .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?,
                stream_initialization_digest: state.envelope.stream_initialization_digest.clone(),
            },
        );
        if let Some(secondary) = self
            .secondary_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            validated_streams.insert(
                secondary.envelope.stream_id.clone(),
                WitnessStoreProxyValidatedEntryV1 {
                    schema_version: PROTOCOL_SCHEMA_VERSION,
                    revision: secondary.revision,
                    store_state_digest: secondary
                        .envelope
                        .store_state_digest()
                        .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?,
                    stream_initialization_digest: secondary
                        .envelope
                        .stream_initialization_digest
                        .clone(),
                },
            );
        }
        let mutation = *self
            .ready_mutation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut operation = WitnessStoreProxyOperationV1::InspectReady;
        let mut request_digest = request.request_digest;
        let mut bucket_configuration_digest = manifest.bucket_configuration_digest.clone();
        match mutation {
            ReadyMutation::None => {}
            ReadyMutation::WrongOperation => {
                operation = WitnessStoreProxyOperationV1::ReadEntry;
            }
            ReadyMutation::WrongRequestDigest => request_digest = "e".repeat(64),
            ReadyMutation::WrongBucketConfiguration => {
                bucket_configuration_digest = "a".repeat(64);
                manifest.bucket_configuration_digest = bucket_configuration_digest.clone();
                manifest.signature = self.ready_signer.sign(
                    &manifest
                        .signing_bytes()
                        .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?,
                );
            }
            ReadyMutation::WrongManifestDigest => {
                let stream_key = witness_stream_key(&state.envelope.stream_id)
                    .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;
                manifest
                    .initialized_streams
                    .get_mut(&stream_key)
                    .ok_or(PublicWitnessProxyTransportErrorV1::Framing)?
                    .empty_envelope_digest = "e".repeat(64);
                manifest.signature = self.ready_signer.sign(
                    &manifest
                        .signing_bytes()
                        .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?,
                );
            }
            ReadyMutation::WrongManifestPhase => {
                manifest.phase = WitnessBucketManifestPhaseV1::Initializing;
                manifest.signature = self.ready_signer.sign(
                    &manifest
                        .signing_bytes()
                        .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?,
                );
            }
            ReadyMutation::WrongManifestEpoch => {
                manifest.bucket_epoch_digest = "e".repeat(64);
                manifest.signature = self.ready_signer.sign(
                    &manifest
                        .signing_bytes()
                        .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?,
                );
            }
            ReadyMutation::WrongWitnessIdentity => {
                manifest.witness_identity = "foreign-witness".to_string();
                manifest.signature = self.ready_signer.sign(
                    &manifest
                        .signing_bytes()
                        .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?,
                );
            }
            ReadyMutation::WrongWitnessKey => {
                manifest.witness_key_id = self.foreign_ready_signer.key_id().to_string();
                manifest.signature = self.foreign_ready_signer.sign(
                    &manifest
                        .signing_bytes()
                        .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?,
                );
            }
            ReadyMutation::MissingStream => {
                let entry = validated_streams
                    .remove(&state.envelope.stream_id)
                    .ok_or(PublicWitnessProxyTransportErrorV1::Framing)?;
                validated_streams.insert("foreign-stream".to_string(), entry);
            }
            ReadyMutation::ExtraStream => {
                let entry = validated_streams
                    .get(&state.envelope.stream_id)
                    .cloned()
                    .ok_or(PublicWitnessProxyTransportErrorV1::Framing)?;
                validated_streams.insert("foreign-stream".to_string(), entry);
            }
            ReadyMutation::WrongInitializationDigest => {
                let wrong = "e".repeat(64);
                let stream_key = witness_stream_key(&state.envelope.stream_id)
                    .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;
                manifest
                    .initialized_streams
                    .get_mut(&stream_key)
                    .ok_or(PublicWitnessProxyTransportErrorV1::Framing)?
                    .stream_initialization_digest = wrong.clone();
                manifest.signature = self.ready_signer.sign(
                    &manifest
                        .signing_bytes()
                        .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?,
                );
                validated_streams
                    .get_mut(&state.envelope.stream_id)
                    .ok_or(PublicWitnessProxyTransportErrorV1::Framing)?
                    .stream_initialization_digest = wrong;
            }
            ReadyMutation::WrongSummaryRevision => {
                validated_streams
                    .get_mut(&state.envelope.stream_id)
                    .ok_or(PublicWitnessProxyTransportErrorV1::Framing)?
                    .revision = state.revision + 1;
            }
            ReadyMutation::WrongStoreDigest => {
                let entry = validated_streams
                    .get_mut(&state.envelope.stream_id)
                    .ok_or(PublicWitnessProxyTransportErrorV1::Framing)?;
                entry.store_state_digest = "e".repeat(64);
            }
            ReadyMutation::CrossStreamSummaries => {
                let secondary_stream = self
                    .secondary_state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .as_ref()
                    .ok_or(PublicWitnessProxyTransportErrorV1::Framing)?
                    .envelope
                    .stream_id
                    .clone();
                let primary = validated_streams
                    .remove(&state.envelope.stream_id)
                    .ok_or(PublicWitnessProxyTransportErrorV1::Framing)?;
                let secondary = validated_streams
                    .remove(&secondary_stream)
                    .ok_or(PublicWitnessProxyTransportErrorV1::Framing)?;
                validated_streams.insert(state.envelope.stream_id.clone(), secondary);
                validated_streams.insert(secondary_stream, primary);
            }
        }
        let body = if matches!(mutation, ReadyMutation::WrongOperation) {
            WitnessStoreProxyResponseBodyV1::Refused {
                failure_code: WitnessStoreProxyFailureCodeV1::Admission,
                observed_revision: None,
                observed_value_digest: None,
            }
        } else {
            WitnessStoreProxyResponseBodyV1::Ready {
                nats_stream_created_at: "2026-08-26T00:00:00.000000000Z".to_string(),
                bucket_configuration_digest,
                ready_manifest: Box::new(manifest),
                validated_streams,
            }
        };
        let response = WitnessStoreProxyResponseV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            operation,
            request_digest,
            body,
        };
        response
            .validate()
            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;
        self.ready_valid_responses.fetch_add(1, Ordering::SeqCst);
        Ok(response)
    }

    async fn read_entry(
        &self,
        request: WitnessStoreProxyRequestV1,
    ) -> Result<WitnessStoreProxyResponseV1, PublicWitnessProxyTransportErrorV1> {
        request
            .validate_structure()
            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;
        request
            .validate_signature()
            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;
        let WitnessStoreProxyRequestBodyV1::ReadEntry { stream_id } = &request.body else {
            return Err(PublicWitnessProxyTransportErrorV1::Framing);
        };
        self.calls.fetch_add(1, Ordering::SeqCst);
        let release = self
            .release
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(release) = release {
            self.entered.notify_one();
            release.notified().await;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (revision, envelope) = if stream_id == &state.envelope.stream_id {
            state.events.push("read");
            (state.revision, state.envelope.clone())
        } else {
            drop(state);
            let mut secondary = self
                .secondary_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let secondary = secondary
                .as_mut()
                .filter(|state| stream_id == &state.envelope.stream_id)
                .ok_or(PublicWitnessProxyTransportErrorV1::Framing)?;
            secondary.events.push("read");
            (secondary.revision, secondary.envelope.clone())
        };
        Ok(WitnessStoreProxyResponseV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            operation: WitnessStoreProxyOperationV1::ReadEntry,
            request_digest: request.request_digest,
            body: WitnessStoreProxyResponseBodyV1::Entry {
                stream_id: stream_id.clone(),
                revision,
                envelope: Box::new(envelope),
            },
        })
    }

    async fn compare_and_swap(
        &self,
        request: WitnessStoreProxyRequestV1,
    ) -> Result<WitnessStoreProxyResponseV1, PublicWitnessProxyTransportErrorV1> {
        request
            .validate_structure()
            .and_then(|_| request.validate_semantics())
            .and_then(|_| request.validate_signature())
            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;
        let WitnessStoreProxyRequestBodyV1::CompareAndSwap {
            stream_id,
            expected_revision,
            expected_store_state_digest,
            proposed_envelope,
        } = &request.body
        else {
            return Err(PublicWitnessProxyTransportErrorV1::Framing);
        };
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if stream_id != &state.envelope.stream_id {
            drop(state);
            let mut secondary = self
                .secondary_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let state = secondary
                .as_mut()
                .filter(|state| stream_id == &state.envelope.stream_id)
                .ok_or(PublicWitnessProxyTransportErrorV1::Framing)?;
            if *expected_revision != state.revision
                || expected_store_state_digest
                    != &state
                        .envelope
                        .store_state_digest()
                        .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?
                || *self
                    .cas_mode
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    != CasMode::Apply
            {
                return Err(PublicWitnessProxyTransportErrorV1::Framing);
            }
            state.events.push("cas");
            self.cas_attempted.fetch_add(1, Ordering::SeqCst);
            let previous_revision = state.revision;
            state.revision = state
                .revision
                .checked_add(12)
                .ok_or(PublicWitnessProxyTransportErrorV1::Framing)?;
            state.envelope = proposed_envelope.as_ref().clone();
            self.cas_applied.fetch_add(1, Ordering::SeqCst);
            return Ok(WitnessStoreProxyResponseV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                operation: WitnessStoreProxyOperationV1::CompareAndSwap,
                request_digest: request.request_digest,
                body: WitnessStoreProxyResponseBodyV1::CasApplied {
                    stream_id: stream_id.clone(),
                    previous_revision,
                    new_revision: state.revision,
                    acknowledged_value_digest: state
                        .envelope
                        .signed_envelope_digest()
                        .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?,
                },
            });
        }
        if stream_id != &state.envelope.stream_id
            || *expected_revision != state.revision
            || expected_store_state_digest
                != &state
                    .envelope
                    .store_state_digest()
                    .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?
        {
            return Err(PublicWitnessProxyTransportErrorV1::Framing);
        }
        state.events.push("cas");
        self.cas_attempted.fetch_add(1, Ordering::SeqCst);
        let cas_mode = *self
            .cas_mode
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cas_mode == CasMode::Refuse {
            return Ok(WitnessStoreProxyResponseV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                operation: WitnessStoreProxyOperationV1::CompareAndSwap,
                request_digest: request.request_digest,
                body: WitnessStoreProxyResponseBodyV1::Refused {
                    failure_code: WitnessStoreProxyFailureCodeV1::Conflict,
                    observed_revision: Some(state.revision),
                    observed_value_digest: Some(
                        state
                            .envelope
                            .signed_envelope_digest()
                            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?,
                    ),
                },
            });
        }
        if cas_mode == CasMode::ConflictWinner {
            let (observed_revision, observed_envelope) = self
                .conflict_observed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
                .ok_or(PublicWitnessProxyTransportErrorV1::Framing)?;
            return Ok(WitnessStoreProxyResponseV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                operation: WitnessStoreProxyOperationV1::CompareAndSwap,
                request_digest: request.request_digest,
                body: WitnessStoreProxyResponseBodyV1::Conflict {
                    stream_id: stream_id.clone(),
                    observed_revision,
                    observed_envelope: Box::new(observed_envelope),
                },
            });
        }
        if cas_mode == CasMode::Conflict {
            return Ok(WitnessStoreProxyResponseV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                operation: WitnessStoreProxyOperationV1::CompareAndSwap,
                request_digest: request.request_digest,
                body: WitnessStoreProxyResponseBodyV1::Conflict {
                    stream_id: stream_id.clone(),
                    observed_revision: state
                        .revision
                        .checked_add(1)
                        .ok_or(PublicWitnessProxyTransportErrorV1::Framing)?,
                    observed_envelope: Box::new(state.envelope.clone()),
                },
            });
        }
        let previous_revision = state.revision;
        state.revision = state
            .revision
            .checked_add(12)
            .ok_or(PublicWitnessProxyTransportErrorV1::Framing)?;
        state.envelope = proposed_envelope.as_ref().clone();
        let acknowledged_value_digest = state
            .envelope
            .signed_envelope_digest()
            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;
        self.cas_applied.fetch_add(1, Ordering::SeqCst);
        if cas_mode == CasMode::ApplyThenUnavailable {
            return Err(PublicWitnessProxyTransportErrorV1::Unavailable);
        }
        if cas_mode == CasMode::ApplyThenConfirmationSubstitute {
            state.envelope = self
                .confirmation_observed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
                .ok_or(PublicWitnessProxyTransportErrorV1::Framing)?;
        }
        if cas_mode == CasMode::AckWrongKind {
            return Ok(WitnessStoreProxyResponseV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                operation: WitnessStoreProxyOperationV1::ReadEntry,
                request_digest: request.request_digest,
                body: WitnessStoreProxyResponseBodyV1::Entry {
                    stream_id: stream_id.clone(),
                    revision: state.revision,
                    envelope: Box::new(state.envelope.clone()),
                },
            });
        }
        if cas_mode == CasMode::AckUnknown {
            return Ok(WitnessStoreProxyResponseV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                operation: WitnessStoreProxyOperationV1::CompareAndSwap,
                request_digest: request.request_digest,
                body: WitnessStoreProxyResponseBodyV1::Refused {
                    failure_code: WitnessStoreProxyFailureCodeV1::Ambiguous,
                    observed_revision: None,
                    observed_value_digest: None,
                },
            });
        }
        Ok(WitnessStoreProxyResponseV1 {
            schema_version: if cas_mode == CasMode::AckMalformed {
                PROTOCOL_SCHEMA_VERSION + 1
            } else {
                PROTOCOL_SCHEMA_VERSION
            },
            operation: WitnessStoreProxyOperationV1::CompareAndSwap,
            request_digest: if cas_mode == CasMode::AckWrongRequestDigest {
                "f".repeat(64)
            } else {
                request.request_digest
            },
            body: WitnessStoreProxyResponseBodyV1::CasApplied {
                stream_id: if cas_mode == CasMode::AckWrongStream {
                    "foreign-stream".to_string()
                } else {
                    stream_id.clone()
                },
                previous_revision: if cas_mode == CasMode::AckWrongPreviousRevision {
                    previous_revision + 1
                } else {
                    previous_revision
                },
                new_revision: if cas_mode == CasMode::AckDuplicate {
                    previous_revision
                } else if cas_mode == CasMode::AckLower {
                    previous_revision - 1
                } else if cas_mode == CasMode::AckWrongNewRevision {
                    state.revision + 1
                } else {
                    state.revision
                },
                acknowledged_value_digest: if cas_mode == CasMode::AckWrongDigest {
                    "f".repeat(64)
                } else {
                    acknowledged_value_digest
                },
            },
        })
    }
}

#[tokio::test]
async fn public_dispatcher_rejects_unknown_subject_operation_or_body() -> ProtocolResult<()> {
    let fixture = Fixture::new(CasMode::Apply)?;
    let dispatcher = fixture.dispatcher().await.map_err(dispatch_error)?;
    let request = fixture.fence_request()?;
    let bytes = request.canonical_bytes()?;
    let before = fixture.proxy.calls.load(Ordering::SeqCst);
    assert!(
        dispatcher
            .dispatch("swarm.governance.witness.v1.unknown", &bytes)
            .await
            .is_err()
    );
    assert!(
        dispatcher
            .dispatch("swarm.governance.witness.v1.commit", &bytes)
            .await
            .is_err()
    );
    assert_eq!(fixture.proxy.calls.load(Ordering::SeqCst), before);

    let expected = [
        (
            "issue_session_fence",
            WitnessServiceOperationV1::Fence,
            "Fence",
            false,
        ),
        (
            "establish_session",
            WitnessServiceOperationV1::Establish,
            "Establish",
            false,
        ),
        (
            "discover_stream",
            WitnessServiceOperationV1::Discover,
            "Discover",
            false,
        ),
        (
            "prepare_successor",
            WitnessServiceOperationV1::Prepare,
            "Outcome",
            true,
        ),
        (
            "commit_prepared",
            WitnessServiceOperationV1::Commit,
            "Outcome",
            true,
        ),
        (
            "abort_prepared",
            WitnessServiceOperationV1::Abort,
            "Outcome",
            true,
        ),
        (
            "read_prepared_for_stream",
            WitnessServiceOperationV1::ReadPrepared,
            "Read",
            true,
        ),
        (
            "read_head",
            WitnessServiceOperationV1::ReadHead,
            "Read",
            true,
        ),
        (
            "fetch_payload",
            WitnessServiceOperationV1::FetchPayload,
            "Read",
            true,
        ),
    ];
    for (actual, expected) in dispatcher_mapping().iter().zip(expected) {
        assert_eq!(
            (
                actual.method,
                actual.operation,
                actual.response_variant,
                actual.session_authorization
            ),
            expected
        );
        assert_eq!(
            actual.subject,
            PublicWitnessServiceConfigV1::subject_for(actual.operation)
        );
    }

    let mut wrong_admission = fixture.fence_request()?;
    wrong_admission.admission_digest = "e".repeat(64);
    wrong_admission.request_digest = wrong_admission.computed_digest()?;
    wrong_admission.validate()?;
    let before = fixture.proxy.calls.load(Ordering::SeqCst);
    assert!(
        dispatcher
            .dispatch(
                PublicWitnessServiceConfigV1::subject_for(wrong_admission.operation),
                &wrong_admission.canonical_bytes()?,
            )
            .await
            .is_err()
    );
    assert_eq!(fixture.proxy.calls.load(Ordering::SeqCst), before);

    for (mutation, expected_startup_reads) in [
        (ReadyMutation::WrongOperation, 0),
        (ReadyMutation::WrongRequestDigest, 0),
        (ReadyMutation::WrongBucketConfiguration, 0),
        (ReadyMutation::WrongManifestDigest, 0),
        (ReadyMutation::WrongManifestPhase, 0),
        (ReadyMutation::WrongManifestEpoch, 0),
        (ReadyMutation::WrongWitnessIdentity, 0),
        (ReadyMutation::WrongWitnessKey, 0),
        (ReadyMutation::MissingStream, 0),
        (ReadyMutation::ExtraStream, 0),
        (ReadyMutation::WrongInitializationDigest, 0),
        (ReadyMutation::WrongSummaryRevision, 1),
        (ReadyMutation::WrongStoreDigest, 1),
    ] {
        let ready_fixture = Fixture::new(CasMode::Apply)?;
        ready_fixture.set_ready_mutation(mutation);
        assert!(ready_fixture.dispatcher().await.is_err());
        assert_eq!(ready_fixture.proxy.inspect_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            ready_fixture
                .proxy
                .ready_valid_responses
                .load(Ordering::SeqCst),
            1
        );
        assert_eq!(
            ready_fixture.proxy.calls.load(Ordering::SeqCst),
            expected_startup_reads
        );
        assert_eq!(
            ready_fixture.proxy.events(),
            vec!["read"; expected_startup_reads]
        );
        assert!(!ready_fixture.proxy.events().contains(&"cas"));
    }
    let ready_fixture = Fixture::new(CasMode::Apply)?;
    ready_fixture.mutate_manifest_admission()?;
    assert!(ready_fixture.dispatcher().await.is_err());
    assert_eq!(ready_fixture.proxy.inspect_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        ready_fixture
            .proxy
            .ready_valid_responses
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(ready_fixture.proxy.calls.load(Ordering::SeqCst), 0);
    assert!(ready_fixture.proxy.events().is_empty());

    for field in ["bucket_anchor", "bucket_epoch", "admission"] {
        let ready_fixture = Fixture::new(CasMode::Apply)?;
        let mut config = ready_fixture.config()?;
        match field {
            "bucket_anchor" => config.bucket_anchor_digest = "e".repeat(64),
            "bucket_epoch" => config.bucket_epoch_digest = "e".repeat(64),
            "admission" => {
                let admission = &mut config.admission_set.entries[0].admission;
                admission.initial_epoch = 1;
                admission.admission_digest = admission.computed_digest()?;
                config.admission_set.admission_set_digest =
                    config.admission_set.computed_digest()?;
                config.admission_set_digest = config.admission_set.admission_set_digest.clone();
            }
            _ => unreachable!(),
        }
        assert!(
            PublicWitnessDispatcher::new(
                config,
                ready_fixture.witness.clone(),
                ready_fixture.proxy.clone(),
            )
            .await
            .is_err()
        );
        assert_eq!(ready_fixture.proxy.inspect_calls.load(Ordering::SeqCst), 1);
        assert_eq!(ready_fixture.proxy.calls.load(Ordering::SeqCst), 0);
        assert!(ready_fixture.proxy.events().is_empty());
    }
    write_dispatcher_mapping_ledger()?;
    Ok(())
}

#[test]
fn public_dispatcher_returns_overload_without_spawning_or_touching_store() -> ProtocolResult<()> {
    run_corpus_on_bounded_test_stack(public_dispatcher_overload_corpus)
}

async fn public_dispatcher_overload_corpus() -> ProtocolResult<()> {
    assert!(public_witness_ingress_overload_control());
    let fixture = Fixture::new(CasMode::Apply)?;
    let release = Arc::new(Notify::new());
    let entered = fixture.proxy.entered.clone();
    let dispatcher = Arc::new(fixture.dispatcher().await.map_err(dispatch_error)?);
    *fixture
        .proxy
        .release
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(release.clone());
    let request = fixture.fence_request()?;
    let first_dispatcher = dispatcher.clone();
    let first_bytes = request.canonical_bytes()?;
    let first = tokio::spawn(async move {
        first_dispatcher
            .dispatch("swarm.governance.witness.v1.fence", &first_bytes)
            .await
    });
    entered.notified().await;
    let result = dispatcher
        .dispatch(
            "swarm.governance.witness.v1.fence",
            &request.canonical_bytes()?,
        )
        .await;
    assert!(matches!(
        result,
        Err(PublicWitnessDispatchErrorV1::Overloaded)
    ));
    assert_eq!(fixture.proxy.calls.load(Ordering::SeqCst), 1);
    release.notify_one();
    first.await.map_err(join_error)?.map_err(dispatch_error)?;
    Ok(())
}

#[test]
fn public_dispatcher_signs_only_after_confirmed_transition() -> ProtocolResult<()> {
    run_corpus_on_bounded_test_stack(public_dispatcher_success_corpus)
}

async fn public_dispatcher_success_corpus() -> ProtocolResult<()> {
    let mut two_stream = Fixture::new(CasMode::Apply)?;
    let second = two_stream.enable_second_stream()?;
    let two_stream_dispatcher = two_stream.dispatcher().await.map_err(dispatch_error)?;
    let response = two_stream
        .dispatch_request(&two_stream_dispatcher, &second.fence_request)
        .await?;
    assert!(matches!(response, WitnessServiceResponseV1::Fence(_)));
    assert_eq!(two_stream.proxy.inspect_calls.load(Ordering::SeqCst), 1);
    assert_eq!(two_stream.proxy.calls.load(Ordering::SeqCst), 1);
    assert!(two_stream.proxy.events().is_empty());
    assert_eq!(
        two_stream
            .proxy
            .secondary_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?
            .events,
        vec!["read"]
    );

    let fixture = Fixture::new(CasMode::Apply)?;
    let dispatcher = fixture.dispatcher().await.map_err(dispatch_error)?;

    let read_request = fixture.read_prepared_request()?;
    let read_bytes = dispatcher
        .dispatch(
            PublicWitnessServiceConfigV1::subject_for(read_request.operation),
            &read_request.canonical_bytes()?,
        )
        .await
        .map_err(dispatch_error)?;
    assert!(matches!(
        WitnessServiceResponseV1::decode_for_client_request(&read_bytes, &read_request)?,
        WitnessServiceResponseV1::Read(_)
    ));
    assert_eq!(fixture.proxy.events(), vec!["read"]);

    let prepare_request = fixture.prepare_request()?;
    let response_bytes = dispatcher
        .dispatch(
            PublicWitnessServiceConfigV1::subject_for(prepare_request.operation),
            &prepare_request.canonical_bytes()?,
        )
        .await
        .map_err(dispatch_error)?;
    assert!(matches!(
        WitnessServiceResponseV1::decode_for_client_request(&response_bytes, &prepare_request)?,
        WitnessServiceResponseV1::Outcome(_)
    ));
    assert_eq!(fixture.proxy.events(), vec!["read", "read", "cas", "read"]);
    {
        let state = fixture
            .proxy
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(state.revision, 19);
        assert!(state.envelope.prepared.is_some());
    }

    let commit_request = fixture.commit_request()?;
    assert!(matches!(
        fixture
            .dispatch_request(&dispatcher, &commit_request)
            .await?,
        WitnessServiceResponseV1::Outcome(_)
    ));
    let commit_events = fixture.proxy.events();
    assert_eq!(
        commit_events,
        vec!["read", "read", "cas", "read", "read", "cas", "read"]
    );
    assert!(matches!(
        fixture
            .dispatch_request(&dispatcher, &commit_request)
            .await?,
        WitnessServiceResponseV1::Outcome(_)
    ));
    assert_eq!(
        fixture.proxy.events(),
        [commit_events, vec!["read"]].concat()
    );

    let establish_fixture = Fixture::new(CasMode::Apply)?;
    let establish_dispatcher = establish_fixture
        .dispatcher()
        .await
        .map_err(dispatch_error)?;
    let establish_request = establish_fixture.establish_request()?;
    let establish_bytes = establish_dispatcher
        .dispatch(
            PublicWitnessServiceConfigV1::subject_for(establish_request.operation),
            &establish_request.canonical_bytes()?,
        )
        .await
        .map_err(dispatch_error)?;
    assert!(matches!(
        WitnessServiceResponseV1::decode_for_client_request(&establish_bytes, &establish_request)?,
        WitnessServiceResponseV1::Establish(_)
    ));
    assert_eq!(
        establish_fixture.proxy.events(),
        vec!["read", "cas", "read"]
    );

    assert!(matches!(
        establish_fixture
            .dispatch_request(&establish_dispatcher, &establish_request)
            .await?,
        WitnessServiceResponseV1::Establish(_)
    ));
    assert_eq!(
        establish_fixture.proxy.events(),
        vec!["read", "cas", "read", "read"]
    );

    let discover_fixture = Fixture::new(CasMode::Apply)?;
    let discover_dispatcher = discover_fixture
        .dispatcher()
        .await
        .map_err(dispatch_error)?;
    let discover_request = discover_fixture.discover_request()?;
    assert!(matches!(
        discover_fixture
            .dispatch_request(&discover_dispatcher, &discover_request)
            .await?,
        WitnessServiceResponseV1::Discover(_)
    ));
    assert!(matches!(
        discover_fixture
            .dispatch_request(&discover_dispatcher, &discover_request)
            .await?,
        WitnessServiceResponseV1::Discover(_)
    ));
    assert_eq!(
        discover_fixture.proxy.events(),
        vec!["read", "cas", "read", "read"]
    );

    let abort_fixture = Fixture::new(CasMode::Apply)?;
    let abort_dispatcher = abort_fixture.dispatcher().await.map_err(dispatch_error)?;
    let abort_prepare = abort_fixture.prepare_request()?;
    assert!(matches!(
        abort_fixture
            .dispatch_request(&abort_dispatcher, &abort_prepare)
            .await?,
        WitnessServiceResponseV1::Outcome(_)
    ));
    let abort_request = abort_fixture.abort_request()?;
    assert!(matches!(
        abort_fixture
            .dispatch_request(&abort_dispatcher, &abort_request)
            .await?,
        WitnessServiceResponseV1::Outcome(_)
    ));
    let abort_events = abort_fixture.proxy.events();
    assert_eq!(
        abort_events,
        vec!["read", "cas", "read", "read", "cas", "read"]
    );
    assert!(matches!(
        abort_fixture
            .dispatch_request(&abort_dispatcher, &abort_request)
            .await?,
        WitnessServiceResponseV1::Outcome(_)
    ));
    assert_eq!(
        abort_fixture.proxy.events(),
        [abort_events, vec!["read"]].concat()
    );

    assert_lost_response_remains_unknown(OperationCase::Establish).await?;
    assert_lost_response_remains_unknown(OperationCase::Discover).await?;
    assert_lost_response_remains_unknown(OperationCase::Prepare).await?;
    assert_lost_response_remains_unknown(OperationCase::Commit).await?;
    assert_lost_response_remains_unknown(OperationCase::Abort).await?;
    assert_post_cas_acknowledgements_remain_unknown().await?;
    assert_prepare_idempotency_and_recovery().await?;
    assert_cross_operation_winners().await?;
    assert_genesis_abort_successor_after_restart().await?;
    Ok(())
}

#[test]
fn public_dispatcher_maps_typed_failure_without_string_fallback() -> ProtocolResult<()> {
    run_corpus_on_bounded_test_stack(public_dispatcher_failure_corpus)
}

async fn public_dispatcher_failure_corpus() -> ProtocolResult<()> {
    assert_bound_taxonomy_is_seam_specific().await?;
    assert_authenticated_entry_limits_are_enforced().await?;
    assert_pre_store_admission_fences().await?;
    assert_multistream_startup_controls().await?;
    assert_prepare_admission_classification().await?;
    let fixture = Fixture::new(CasMode::Refuse)?;
    let dispatcher = fixture.dispatcher().await.map_err(dispatch_error)?;
    let request = fixture.prepare_request()?;
    let bytes = dispatcher
        .dispatch(
            PublicWitnessServiceConfigV1::subject_for(request.operation),
            &request.canonical_bytes()?,
        )
        .await
        .map_err(dispatch_error)?;
    let WitnessServiceResponseV1::Failure(failure) =
        WitnessServiceResponseV1::decode_for_client_request(&bytes, &request)?
    else {
        panic!("dispatcher returned a non-failure response");
    };
    assert_eq!(failure.failure_code, WitnessServiceFailureCodeV1::Conflict);
    assert!(!failure.retryable);
    let response_text = String::from_utf8(bytes)
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    assert!(!response_text.contains("error_message"));
    assert_eq!(fixture.proxy.events(), vec!["read", "cas"]);
    assert_typed_conflict(OperationCase::Establish).await?;
    assert_typed_conflict(OperationCase::Discover).await?;
    assert_typed_conflict(OperationCase::Commit).await?;
    assert_typed_conflict(OperationCase::Abort).await?;
    assert_stale_reads_after_rotations(1).await?;
    assert_stale_reads_after_rotations(100).await?;
    assert_stale_rotation_failure_is_signed().await?;
    assert_complete_signed_application_failures().await?;
    Ok(())
}

async fn assert_bound_taxonomy_is_seam_specific() -> ProtocolResult<()> {
    for field in ["state", "checkpoint", "binding", "retained"] {
        for exceeds in [false, true] {
            let mut startup = Fixture::new(CasMode::Apply)?;
            let candidate = bound_candidate(&startup, field, exceeds)?;
            let prepared = startup.envelope_with_prepared_candidate(&candidate)?;
            let ceiling = bound_ceiling(&startup, field, &prepared, exceeds)?;
            startup.configure_primary_entry(|entry| set_entry_bound(entry, field, ceiling))?;
            let prepared = startup.envelope_with_prepared_candidate(&candidate)?;
            replace_primary_envelope(&startup, prepared.clone())?;
            let startup_result = startup.dispatcher().await;
            assert_eq!(startup_result.is_err(), exceeds, "startup {field}");
            if exceeds {
                assert_eq!(startup.proxy.inspect_calls.load(Ordering::SeqCst), 1);
                assert_eq!(startup.proxy.events(), vec!["read"]);
            }
            assert_eq!(startup.proxy.cas_attempted.load(Ordering::SeqCst), 0);
            assert_eq!(startup.proxy.cas_applied.load(Ordering::SeqCst), 0);

            let mut initial = Fixture::new(CasMode::Apply)?;
            let candidate = bound_candidate(&initial, field, exceeds)?;
            let prepared = initial.envelope_with_prepared_candidate(&candidate)?;
            let ceiling = bound_ceiling(&initial, field, &prepared, exceeds)?;
            initial.configure_primary_entry(|entry| set_entry_bound(entry, field, ceiling))?;
            let dispatcher = initial.dispatcher().await.map_err(dispatch_error)?;
            let prepared = initial.envelope_with_prepared_candidate(&candidate)?;
            let observed_digest = prepared.store_state_digest()?;
            replace_primary_envelope(&initial, prepared)?;
            let response = initial
                .dispatch_outer_valid_request(&dispatcher, &initial.fence_request()?)
                .await?;
            if exceeds {
                let WitnessServiceResponseV1::Failure(failure) = response else {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                };
                assert_eq!(
                    failure.failure_code,
                    WitnessServiceFailureCodeV1::BoundsExceeded
                );
                assert_eq!(failure.store_state_digest, Some(observed_digest));
            } else {
                assert!(matches!(response, WitnessServiceResponseV1::Fence(_)));
            }
            assert_eq!(initial.proxy.events(), vec!["read"]);
            assert_eq!(initial.proxy.cas_attempted.load(Ordering::SeqCst), 0);

            let mut proposed = Fixture::new(CasMode::Apply)?;
            let candidate = bound_candidate(&proposed, field, exceeds)?;
            let prepared = proposed.envelope_with_prepared_candidate(&candidate)?;
            let ceiling = bound_ceiling(&proposed, field, &prepared, exceeds)?;
            proposed.configure_primary_entry(|entry| set_entry_bound(entry, field, ceiling))?;
            let dispatcher = proposed.dispatcher().await.map_err(dispatch_error)?;
            let request = proposed.prepare_request_for_candidate(&candidate)?;
            let response = proposed
                .dispatch_outer_valid_request(&dispatcher, &request)
                .await?;
            if exceeds {
                let WitnessServiceResponseV1::Failure(failure) = response else {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                };
                assert_eq!(
                    failure.failure_code,
                    WitnessServiceFailureCodeV1::BoundsExceeded
                );
                assert_eq!(proposed.proxy.events(), vec!["read"]);
                assert_eq!(proposed.proxy.cas_attempted.load(Ordering::SeqCst), 0);
                assert_eq!(proposed.proxy.cas_applied.load(Ordering::SeqCst), 0);
            } else {
                assert!(matches!(response, WitnessServiceResponseV1::Outcome(_)));
                assert_eq!(proposed.proxy.events(), vec!["read", "cas", "read"]);
                assert_eq!(proposed.proxy.cas_attempted.load(Ordering::SeqCst), 1);
                assert_eq!(proposed.proxy.cas_applied.load(Ordering::SeqCst), 1);
            }

            let mut conflict = Fixture::new(CasMode::Apply)?;
            let candidate = bound_candidate(&conflict, field, exceeds)?;
            let prepared = conflict.envelope_with_prepared_candidate(&candidate)?;
            let ceiling = bound_ceiling(&conflict, field, &prepared, exceeds)?;
            conflict.configure_primary_entry(|entry| set_entry_bound(entry, field, ceiling))?;
            let dispatcher = conflict.dispatcher().await.map_err(dispatch_error)?;
            let prepared = conflict.envelope_with_prepared_candidate(&candidate)?;
            let winner_digest = prepared.store_state_digest()?;
            conflict.set_conflict_observed(conflict.store_snapshot().0 + 1, prepared);
            let response = conflict
                .dispatch_request(&dispatcher, &conflict.establish_request()?)
                .await?;
            let WitnessServiceResponseV1::Failure(failure) = response else {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            };
            assert_eq!(
                failure.failure_code,
                if exceeds {
                    WitnessServiceFailureCodeV1::BoundsExceeded
                } else {
                    WitnessServiceFailureCodeV1::Conflict
                }
            );
            if exceeds {
                assert_eq!(failure.store_state_digest, Some(winner_digest));
            }
            assert_eq!(conflict.proxy.events(), vec!["read", "cas"]);
            assert_eq!(conflict.proxy.cas_attempted.load(Ordering::SeqCst), 1);
            assert_eq!(conflict.proxy.cas_applied.load(Ordering::SeqCst), 0);

            let mut confirmation = Fixture::new(CasMode::Apply)?;
            let candidate = bound_candidate(&confirmation, field, exceeds)?;
            let prepared = confirmation.envelope_with_prepared_candidate(&candidate)?;
            let ceiling = bound_ceiling(&confirmation, field, &prepared, exceeds)?;
            confirmation.configure_primary_entry(|entry| set_entry_bound(entry, field, ceiling))?;
            let dispatcher = confirmation.dispatcher().await.map_err(dispatch_error)?;
            if exceeds {
                let prepared = confirmation.envelope_with_prepared_candidate(&candidate)?;
                confirmation.set_confirmation_observed(prepared);
                let request = confirmation.establish_request()?;
                assert!(matches!(
                    dispatcher
                        .dispatch(
                            PublicWitnessServiceConfigV1::subject_for(request.operation),
                            &request.canonical_bytes()?,
                        )
                        .await,
                    Err(PublicWitnessDispatchErrorV1::OutcomeUnknown)
                ));
            } else {
                assert!(matches!(
                    confirmation
                        .dispatch_request(
                            &dispatcher,
                            &confirmation.prepare_request_for_candidate(&candidate)?,
                        )
                        .await?,
                    WitnessServiceResponseV1::Outcome(_)
                ));
            }
            assert_eq!(confirmation.proxy.events(), vec!["read", "cas", "read"]);
            assert_eq!(confirmation.proxy.cas_attempted.load(Ordering::SeqCst), 1);
            assert_eq!(confirmation.proxy.cas_applied.load(Ordering::SeqCst), 1);
        }
    }
    Ok(())
}

fn bound_candidate(fixture: &Fixture, field: &str, exceeds: bool) -> ProtocolResult<CandidateV1> {
    match (field, exceeds) {
        ("state", true) => fixture.candidate_with_larger_state(),
        ("checkpoint", true) => fixture.candidate_with_larger_checkpoint(),
        ("state" | "checkpoint" | "binding" | "retained", _) => Ok(fixture.candidate.clone()),
        _ => Err(ProtocolError::WitnessOutcomeMismatch),
    }
}

fn bound_ceiling(
    fixture: &Fixture,
    field: &str,
    prepared: &WitnessStoreEnvelopeV1,
    exceeds: bool,
) -> ProtocolResult<u64> {
    let exact = match field {
        "state" => fixture.candidate.preimage.state_byte_len,
        "checkpoint" => fixture.candidate.preimage.checkpoint_byte_len,
        "binding" => canonical_wire_bytes(&fixture.binding)?.len() as u64,
        "retained" => (canonical_wire_bytes(prepared)?.len() as u64).max(
            prepared
                .prepared
                .as_ref()
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?
                .candidate
                .state_byte_len
                + prepared
                    .prepared
                    .as_ref()
                    .ok_or(ProtocolError::WitnessOutcomeMismatch)?
                    .candidate
                    .checkpoint_byte_len,
        ),
        _ => return Err(ProtocolError::WitnessOutcomeMismatch),
    };
    if exceeds && matches!(field, "binding" | "retained") {
        exact.checked_sub(1).ok_or(ProtocolError::Overflow {
            counter: "selected_entry_bound",
        })
    } else {
        Ok(exact)
    }
}

fn set_entry_bound(entry: &mut WitnessAdmissionEntryV1, field: &str, ceiling: u64) {
    match field {
        "state" => entry.max_state_bytes = ceiling,
        "checkpoint" => entry.max_checkpoint_bytes = ceiling,
        "binding" => entry.max_binding_bytes = ceiling,
        "retained" => entry.admission.max_retained_bytes = ceiling,
        _ => unreachable!(),
    }
}

fn replace_primary_envelope(
    fixture: &Fixture,
    envelope: WitnessStoreEnvelopeV1,
) -> ProtocolResult<()> {
    envelope.validate()?;
    let mut state = fixture
        .proxy
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    state.envelope = envelope;
    state.revision = state
        .revision
        .checked_add(1)
        .ok_or(ProtocolError::Overflow {
            counter: "revision",
        })?;
    Ok(())
}

async fn assert_prepare_admission_classification() -> ProtocolResult<()> {
    for (roles, limits, intent, expected) in [
        (
            true,
            false,
            1,
            WitnessServiceFailureCodeV1::AdmissionMismatch,
        ),
        (
            false,
            true,
            1,
            WitnessServiceFailureCodeV1::AdmissionMismatch,
        ),
        (false, false, 2, WitnessServiceFailureCodeV1::StaleIntent),
        (
            true,
            false,
            2,
            WitnessServiceFailureCodeV1::AdmissionMismatch,
        ),
        (
            false,
            true,
            2,
            WitnessServiceFailureCodeV1::AdmissionMismatch,
        ),
    ] {
        let fixture = Fixture::new(CasMode::Apply)?;
        let dispatcher = fixture.dispatcher().await.map_err(dispatch_error)?;
        let mut binding = fixture.binding.clone();
        if roles {
            binding.publication_roles.state_canonical = artifact(901);
        }
        if limits {
            binding.limits.max_payload_bytes = binding
                .limits
                .max_payload_bytes
                .checked_sub(1)
                .ok_or(ProtocolError::Overflow {
                    counter: "max_payload_bytes",
                })?;
        }
        binding.binding_digest = binding.computed_digest()?;
        binding.binding_signature = fixture.governance.sign(&binding.signing_bytes()?);
        binding.validate()?;
        let mut preimage = candidate(&fixture.governance, &binding)?;
        preimage.intent_counter = intent;
        let candidate = preimage.build()?;
        candidate.validate()?;
        let target_txid = candidate.txid.clone();
        let mut request = fixture.prepare_request()?;
        let WitnessServiceRequestBodyV1::Prepare {
            candidate: request_candidate,
            ..
        } = &mut request.body
        else {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        };
        **request_candidate = candidate;
        rebind_outer_request(
            &mut request,
            &fixture.ephemeral,
            &fixture.session,
            WitnessOperationV1::Prepare,
            &target_txid,
        )?;
        request.validate_public_dispatch_identity()?;
        assert_signed_application_failure(&fixture, &dispatcher, &request, expected).await?;
        assert_eq!(fixture.proxy.events(), vec!["read"]);
    }

    // Wrong intent combined with a separately invalid admitted genesis
    // epoch or sequence is not an intent-only failure.
    for (initial_epoch, initial_sequence) in [(1, 0), (0, 1)] {
        let fixture =
            Fixture::new_with_initial_values(CasMode::Apply, initial_epoch, initial_sequence, 2)?;
        let dispatcher = fixture.dispatcher().await.map_err(dispatch_error)?;
        let request = fixture.prepare_request()?;
        request.validate_public_dispatch_identity()?;
        assert_signed_application_failure(
            &fixture,
            &dispatcher,
            &request,
            WitnessServiceFailureCodeV1::AdmissionMismatch,
        )
        .await?;
        assert_eq!(fixture.proxy.events(), vec!["read"]);
    }

    for corruption in [
        "authorization_signature",
        "state_signature",
        "checkpoint_signature",
        "predecessor_digest",
    ] {
        let fixture = Fixture::new_with_initial_intent(CasMode::Apply, 2)?;
        let dispatcher = fixture.dispatcher().await.map_err(dispatch_error)?;
        let mut request = fixture.prepare_request()?;
        match corruption {
            "authorization_signature" => {
                request
                    .authorization
                    .as_mut()
                    .ok_or(ProtocolError::WitnessOutcomeMismatch)?
                    .signature
                    .signature_hex = "0".repeat(128);
            }
            state => {
                let WitnessServiceRequestBodyV1::Prepare { candidate, .. } = &mut request.body
                else {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                };
                match state {
                    "state_signature" => {
                        candidate.preimage.state_attestation.signature_hex = "0".repeat(128);
                    }
                    "checkpoint_signature" => {
                        candidate.preimage.checkpoint_attestation.signature_hex = "0".repeat(128);
                    }
                    "predecessor_digest" => {
                        candidate.preimage.predecessor_head_digest = "e".repeat(64);
                    }
                    _ => return Err(ProtocolError::WitnessOutcomeMismatch),
                }
                rebind_outer_request(
                    &mut request,
                    &fixture.ephemeral,
                    &fixture.session,
                    WitnessOperationV1::Prepare,
                    &fixture.candidate.txid,
                )?;
            }
        }
        assert_signed_application_failure(
            &fixture,
            &dispatcher,
            &request,
            WitnessServiceFailureCodeV1::InvalidSignature,
        )
        .await?;
        assert_eq!(fixture.proxy.events(), vec!["read"]);
    }

    let fixture = Fixture::new_with_initial_intent(CasMode::Apply, 2)?;
    let dispatcher = fixture.dispatcher().await.map_err(dispatch_error)?;
    let mut preimage = candidate(&fixture.governance, &fixture.binding)?;
    std::mem::swap(
        &mut preimage.publication_mapping_before,
        &mut preimage.publication_mapping_after,
    );
    let swapped_candidate = preimage.build()?;
    let request = fixture.prepare_request_for_candidate(&swapped_candidate)?;
    request.validate()?;
    assert_signed_application_failure(
        &fixture,
        &dispatcher,
        &request,
        WitnessServiceFailureCodeV1::AdmissionMismatch,
    )
    .await?;
    assert_eq!(fixture.proxy.events(), vec!["read"]);

    // The same precedence is retained after a persisted genesis abort: only
    // the exact immediate successor relation is eligible for intent-only.
    let fixture = Fixture::new(CasMode::Apply)?;
    let dispatcher = fixture.dispatcher().await.map_err(dispatch_error)?;
    fixture
        .dispatch_request(&dispatcher, &fixture.prepare_request()?)
        .await?;
    fixture
        .dispatch_request(&dispatcher, &fixture.abort_request()?)
        .await?;
    fixture.proxy.reset_observations();
    let mut preimage = candidate(&fixture.governance, &fixture.binding)?;
    preimage.intent_counter = 2;
    std::mem::swap(
        &mut preimage.publication_mapping_before,
        &mut preimage.publication_mapping_after,
    );
    let candidate = preimage.build()?;
    let request = fixture.prepare_request_for_candidate(&candidate)?;
    assert_signed_application_failure(
        &fixture,
        &dispatcher,
        &request,
        WitnessServiceFailureCodeV1::AdmissionMismatch,
    )
    .await?;
    assert_eq!(fixture.proxy.events(), vec!["read"]);
    assert_current_head_intent_classification().await?;
    Ok(())
}

async fn assert_current_head_intent_classification() -> ProtocolResult<()> {
    let fixture = Fixture::new(CasMode::Apply)?;
    let dispatcher = fixture.dispatcher().await.map_err(dispatch_error)?;
    assert!(matches!(
        fixture
            .dispatch_request(&dispatcher, &fixture.prepare_request()?)
            .await?,
        WitnessServiceResponseV1::Outcome(_)
    ));
    assert!(matches!(
        fixture
            .dispatch_request(&dispatcher, &fixture.commit_request()?)
            .await?,
        WitnessServiceResponseV1::Outcome(_)
    ));
    fixture.proxy.reset_observations();
    let head = fixture
        .store_snapshot()
        .1
        .current
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .head;
    let expected_intent = head
        .intent_counter
        .checked_add(1)
        .ok_or(ProtocolError::Overflow {
            counter: "intent_counter",
        })?;
    for intent in [
        head.intent_counter,
        expected_intent
            .checked_add(1)
            .ok_or(ProtocolError::Overflow {
                counter: "intent_counter",
            })?,
    ] {
        let candidate = fixture.candidate_after_head_with_intent(&head, intent)?;
        let request = fixture.prepare_request_for_current_candidate(&candidate, &head)?;
        assert_signed_application_failure(
            &fixture,
            &dispatcher,
            &request,
            WitnessServiceFailureCodeV1::StaleIntent,
        )
        .await?;
        assert_eq!(fixture.proxy.events(), vec!["read"]);
        fixture.proxy.reset_observations();
    }

    let mut mixed = fixture.candidate_after_head_with_intent(&head, head.intent_counter)?;
    mixed.preimage.state_attestation.signature_hex = "0".repeat(128);
    mixed = build_candidate_without_intent_relation(mixed.preimage)?;
    let request = fixture.prepare_request_for_current_candidate(&mixed, &head)?;
    assert_signed_application_failure(
        &fixture,
        &dispatcher,
        &request,
        WitnessServiceFailureCodeV1::InvalidSignature,
    )
    .await?;
    assert_eq!(fixture.proxy.events(), vec!["read"]);
    Ok(())
}

async fn assert_authenticated_entry_limits_are_enforced() -> ProtocolResult<()> {
    let mut baseline = Fixture::new(CasMode::Apply)?;
    let secondary = baseline.enable_second_stream()?;
    let request_len = secondary.fence_request.canonical_bytes()?.len() as u64;
    let dispatcher = baseline.dispatcher().await.map_err(dispatch_error)?;
    let response_len = dispatcher
        .dispatch(
            PublicWitnessServiceConfigV1::subject_for(secondary.fence_request.operation),
            &secondary.fence_request.canonical_bytes()?,
        )
        .await
        .map_err(dispatch_error)?
        .len() as u64;
    baseline.proxy.reset_observations();
    assert!(matches!(
        baseline
            .dispatch_request(&dispatcher, &secondary.prepare_request)
            .await?,
        WitnessServiceResponseV1::Outcome(_)
    ));
    assert_eq!(baseline.secondary_events()?, vec!["read", "cas", "read"]);
    let proposed = baseline
        .secondary_snapshot()?
        .1
        .prepared
        .as_ref()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .candidate
        .clone();
    let proposed_envelope = baseline.secondary_snapshot()?.1;
    let state_len = proposed.state_payload.len() as u64;
    let checkpoint_len = proposed.checkpoint_payload.len() as u64;
    let binding_len = canonical_wire_bytes(&proposed.publication_binding)?.len() as u64;
    let retained_len =
        (canonical_wire_bytes(&proposed_envelope)?.len() as u64).max(state_len + checkpoint_len);

    for (field, exact) in [
        ("state", state_len),
        ("checkpoint", checkpoint_len),
        ("binding", binding_len),
        ("retained", retained_len),
    ] {
        assert!(exact > 1, "{field} fixture must support max+1 control");
        for exceeds in [false, true] {
            let ceiling = exact - u64::from(exceeds);
            let mut fixture = Fixture::new(CasMode::Apply)?;
            let secondary = fixture.enable_second_stream_with(|entry| match field {
                "state" => entry.max_state_bytes = ceiling,
                "checkpoint" => entry.max_checkpoint_bytes = ceiling,
                "binding" => entry.max_binding_bytes = ceiling,
                "retained" => entry.admission.max_retained_bytes = ceiling,
                _ => unreachable!(),
            })?;
            let dispatcher = fixture.dispatcher().await.map_err(dispatch_error)?;
            fixture.proxy.reset_observations();
            let result = fixture
                .dispatch_request(&dispatcher, &secondary.prepare_request)
                .await;
            if exceeds {
                let WitnessServiceResponseV1::Failure(failure) = result? else {
                    panic!("{field} max+1 did not return a signed refusal");
                };
                assert_eq!(
                    failure.failure_code,
                    WitnessServiceFailureCodeV1::BoundsExceeded
                );
                assert_eq!(
                    failure.store_state_digest,
                    Some(fixture.secondary_snapshot()?.1.store_state_digest()?)
                );
                assert_eq!(fixture.secondary_events()?, vec!["read"]);
            } else {
                assert!(
                    matches!(result?, WitnessServiceResponseV1::Outcome(_)),
                    "{field} exact maximum was refused"
                );
                assert_eq!(fixture.secondary_events()?, vec!["read", "cas", "read"]);
            }
        }
    }

    for exceeds in [false, true] {
        let ceiling = request_len - u64::from(exceeds);
        let mut fixture = Fixture::new(CasMode::Apply)?;
        let secondary = fixture.enable_second_stream_with(|entry| {
            entry.max_request_bytes = ceiling;
        })?;
        let dispatcher = fixture.dispatcher().await.map_err(dispatch_error)?;
        fixture.proxy.reset_observations();
        let result = dispatcher
            .dispatch(
                PublicWitnessServiceConfigV1::subject_for(secondary.fence_request.operation),
                &secondary.fence_request.canonical_bytes()?,
            )
            .await;
        if exceeds {
            assert!(
                result.is_err(),
                "request max+1 survived selected entry bound"
            );
            assert_eq!(fixture.proxy.calls.load(Ordering::SeqCst), 0);
        } else {
            result.map_err(dispatch_error)?;
            assert_eq!(fixture.secondary_events()?, vec!["read"]);
        }
    }

    for exceeds in [false, true] {
        let ceiling = response_len - u64::from(exceeds);
        let mut fixture = Fixture::new(CasMode::Apply)?;
        let secondary = fixture.enable_second_stream_with(|entry| {
            entry.max_response_bytes = ceiling;
        })?;
        let dispatcher = fixture.dispatcher().await.map_err(dispatch_error)?;
        fixture.proxy.reset_observations();
        let result = dispatcher
            .dispatch(
                PublicWitnessServiceConfigV1::subject_for(secondary.fence_request.operation),
                &secondary.fence_request.canonical_bytes()?,
            )
            .await;
        if exceeds {
            assert!(matches!(
                result,
                Err(PublicWitnessDispatchErrorV1::ResponseBounds)
            ));
            assert_eq!(fixture.secondary_events()?, vec!["read"]);
        } else {
            result.map_err(dispatch_error)?;
            assert_eq!(fixture.secondary_events()?, vec!["read"]);
        }
    }
    Ok(())
}

async fn assert_multistream_startup_controls() -> ProtocolResult<()> {
    for mutation in [
        ReadyMutation::MissingStream,
        ReadyMutation::ExtraStream,
        ReadyMutation::CrossStreamSummaries,
    ] {
        let mut fixture = Fixture::new(CasMode::Apply)?;
        let _ = fixture.enable_second_stream()?;
        fixture.set_ready_mutation(mutation);
        assert!(fixture.dispatcher().await.is_err());
        assert_eq!(fixture.proxy.inspect_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.proxy.calls.load(Ordering::SeqCst), 0);
    }

    let mut duplicate = Fixture::new(CasMode::Apply)?;
    duplicate.admission_set.entries.push(
        duplicate
            .admission_set
            .entries
            .first()
            .cloned()
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?,
    );
    duplicate.admission_set.admission_set_digest = duplicate.admission_set.computed_digest()?;
    assert!(duplicate.dispatcher().await.is_err());
    assert_eq!(duplicate.proxy.inspect_calls.load(Ordering::SeqCst), 0);
    assert_eq!(duplicate.proxy.calls.load(Ordering::SeqCst), 0);

    let mut substituted = Fixture::new(CasMode::Apply)?;
    let entry = substituted
        .admission_set
        .entries
        .first_mut()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    entry.admission.initial_epoch = 1;
    entry.admission.admission_digest = entry.admission.computed_digest()?;
    substituted.admission_set.admission_set_digest = substituted.admission_set.computed_digest()?;
    assert!(substituted.admission_set.validate().is_ok());
    assert!(substituted.dispatcher().await.is_err());
    assert_eq!(substituted.proxy.inspect_calls.load(Ordering::SeqCst), 1);
    assert_eq!(substituted.proxy.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

async fn assert_pre_store_admission_fences() -> ProtocolResult<()> {
    const FIELDS: [&str; 7] = [
        "stream",
        "signer",
        "witness_identity",
        "witness_key",
        "binding_generation",
        "binding_digest",
        "authority_pair",
    ];
    for field in FIELDS {
        let fixture = Fixture::new(CasMode::Apply)?;
        let dispatcher = fixture.dispatcher().await.map_err(dispatch_error)?;
        let foreign_governance =
            Ed25519Signer::from_secret_material("phase285-plan04-foreign-governance-fence");
        let mut request = fixture.fence_request()?;
        let WitnessServiceRequestBodyV1::Fence { request: fence } = &mut request.body else {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        };
        match field {
            "stream" => fence.stream_id = "foreign-stream".to_string(),
            "signer" => fence.signer_key_id = foreign_governance.key_id().to_string(),
            "witness_identity" => fence.witness_identity = "foreign-witness".to_string(),
            "witness_key" => fence.witness_key_id = "e".repeat(64),
            "binding_generation" => fence.binding_generation = "e".repeat(64),
            "binding_digest" => fence.binding_digest = "e".repeat(64),
            "authority_pair" => {
                fence.authority_pair = AuthorityPairIdentityV1 {
                    current: ArtifactIdentityV1 {
                        device: 17,
                        inode: 19,
                    },
                    legacy: ArtifactIdentityV1 {
                        device: 17,
                        inode: 19,
                    },
                };
            }
            _ => return Err(ProtocolError::WitnessOutcomeMismatch),
        }
        let signer = if field == "signer" {
            &foreign_governance
        } else {
            &fixture.governance
        };
        fence.signature = signer.sign(&fence.signing_bytes()?);
        rebind_outer_identity(&mut request)?;
        request.validate()?;
        assert!(
            dispatcher
                .dispatch(
                    PublicWitnessServiceConfigV1::subject_for(request.operation),
                    &request.canonical_bytes()?,
                )
                .await
                .is_err(),
            "fence admission mutation survived: {field}"
        );
        assert_eq!(fixture.proxy.calls.load(Ordering::SeqCst), 0);
    }

    for field in FIELDS {
        let fixture = Fixture::new(CasMode::Apply)?;
        let dispatcher = fixture.dispatcher().await.map_err(dispatch_error)?;
        let foreign_governance =
            Ed25519Signer::from_secret_material("phase285-plan04-foreign-governance-challenge");
        let foreign_witness =
            Ed25519Signer::from_secret_material("phase285-plan04-foreign-witness-challenge");
        let mut request = fixture.establish_request()?;
        let WitnessServiceRequestBodyV1::Establish { challenge, .. } = &mut request.body else {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        };
        let signer = if field == "signer" {
            &foreign_governance
        } else {
            &fixture.governance
        };
        let witness = if field == "witness_key" {
            &foreign_witness
        } else {
            &fixture.witness
        };
        match field {
            "stream" => {
                challenge.stream_id = "foreign-stream".to_string();
                challenge.state_fence.request.stream_id = challenge.stream_id.clone();
            }
            "signer" => {
                challenge.signer_key_id = signer.key_id().to_string();
                challenge.state_fence.request.signer_key_id = signer.key_id().to_string();
            }
            "witness_identity" => {
                challenge.witness_identity = "foreign-witness".to_string();
                challenge.state_fence.request.witness_identity = challenge.witness_identity.clone();
                challenge.state_fence.witness_identity = challenge.witness_identity.clone();
            }
            "witness_key" => {
                challenge.witness_key_id = witness.key_id().to_string();
                challenge.state_fence.request.witness_key_id = witness.key_id().to_string();
                challenge.state_fence.witness_key_id = witness.key_id().to_string();
            }
            "binding_generation" => {
                challenge.binding_generation = "e".repeat(64);
                challenge.state_fence.request.binding_generation = "e".repeat(64);
            }
            "binding_digest" => {
                challenge.binding_digest = "e".repeat(64);
                challenge.state_fence.request.binding_digest = "e".repeat(64);
            }
            "authority_pair" => {
                let authority_pair = AuthorityPairIdentityV1 {
                    current: ArtifactIdentityV1 {
                        device: 23,
                        inode: 29,
                    },
                    legacy: ArtifactIdentityV1 {
                        device: 23,
                        inode: 29,
                    },
                };
                challenge.authority_pair = authority_pair;
                challenge.state_fence.request.authority_pair = authority_pair;
            }
            _ => return Err(ProtocolError::WitnessOutcomeMismatch),
        }
        challenge.state_fence.request.signature =
            signer.sign(&challenge.state_fence.request.signing_bytes()?);
        challenge.state_fence.signature = witness.sign(&challenge.state_fence.signing_bytes()?);
        challenge.signature = signer.sign(&challenge.signing_bytes()?);
        rebind_outer_identity(&mut request)?;
        request.validate()?;
        assert!(
            dispatcher
                .dispatch(
                    PublicWitnessServiceConfigV1::subject_for(request.operation),
                    &request.canonical_bytes()?,
                )
                .await
                .is_err(),
            "challenge admission mutation survived: {field}"
        );
        assert_eq!(fixture.proxy.calls.load(Ordering::SeqCst), 0);
    }

    for field in FIELDS {
        let fixture = Fixture::new(CasMode::Apply)?;
        let dispatcher = fixture.dispatcher().await.map_err(dispatch_error)?;
        let mut request = fixture.read_head_request()?;
        let WitnessServiceRequestBodyV1::ReadHead { session, .. } = &mut request.body else {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        };
        match field {
            "stream" => session.stream_id = "foreign-stream".to_string(),
            "signer" => session.signer_key_id = "e".repeat(64),
            "witness_identity" => session.witness_identity = "foreign-witness".to_string(),
            "witness_key" => session.witness_key_id = "e".repeat(64),
            "binding_generation" => session.binding_generation = "e".repeat(64),
            "binding_digest" => session.binding_digest = "e".repeat(64),
            "authority_pair" => {
                session.authority_pair = AuthorityPairIdentityV1 {
                    current: ArtifactIdentityV1 {
                        device: 31,
                        inode: 37,
                    },
                    legacy: ArtifactIdentityV1 {
                        device: 31,
                        inode: 37,
                    },
                };
            }
            _ => return Err(ProtocolError::WitnessOutcomeMismatch),
        }
        let session = session.as_ref().clone();
        rebind_outer_request(
            &mut request,
            &fixture.ephemeral,
            &session,
            WitnessOperationV1::ReadHead,
            &fixture.candidate.txid,
        )?;
        request.validate()?;
        assert!(
            dispatcher
                .dispatch(
                    PublicWitnessServiceConfigV1::subject_for(request.operation),
                    &request.canonical_bytes()?,
                )
                .await
                .is_err(),
            "session admission mutation survived: {field}"
        );
        assert_eq!(fixture.proxy.calls.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

fn run_corpus_on_bounded_test_stack<F, Fut>(corpus: F) -> ProtocolResult<()>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ProtocolResult<()>> + Send + 'static,
{
    std::thread::Builder::new()
        .name("phase285-public-dispatcher-corpus".to_string())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
            runtime.block_on(corpus())
        })
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?
        .join()
        .map_err(|_| ProtocolError::CanonicalEncoding("dispatcher corpus panicked".to_string()))?
}

#[derive(Clone, Copy)]
enum OperationCase {
    Establish,
    Discover,
    Prepare,
    Commit,
    Abort,
}

async fn operation_request(
    fixture: &Fixture,
    dispatcher: &PublicWitnessDispatcher<RecordingProxy>,
    operation: OperationCase,
) -> ProtocolResult<WitnessServiceRequestV1> {
    if matches!(operation, OperationCase::Commit | OperationCase::Abort) {
        let prepare = fixture.prepare_request()?;
        assert!(matches!(
            fixture.dispatch_request(dispatcher, &prepare).await?,
            WitnessServiceResponseV1::Outcome(_)
        ));
    }
    match operation {
        OperationCase::Establish => fixture.establish_request(),
        OperationCase::Discover => fixture.discover_request(),
        OperationCase::Prepare => fixture.prepare_request(),
        OperationCase::Commit => fixture.commit_request(),
        OperationCase::Abort => fixture.abort_request(),
    }
}

async fn assert_prepare_idempotency_and_recovery() -> ProtocolResult<()> {
    let fixture = Fixture::new(CasMode::Apply)?;
    let dispatcher = fixture.dispatcher().await.map_err(dispatch_error)?;
    let request = fixture.prepare_request()?;
    let WitnessServiceResponseV1::Outcome(initial) =
        fixture.dispatch_request(&dispatcher, &request).await?
    else {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    };
    assert!(matches!(
        initial.outcome,
        WitnessOperationOutcomeV1::Prepare(boxed)
            if matches!(*boxed, WitnessPrepareOutcomeV1::Prepared(_))
    ));
    let attempted = fixture.proxy.cas_attempted.load(Ordering::SeqCst);
    let applied = fixture.proxy.cas_applied.load(Ordering::SeqCst);
    let before_retry = fixture.proxy.events().len();
    let WitnessServiceResponseV1::Outcome(retry) =
        fixture.dispatch_request(&dispatcher, &request).await?
    else {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    };
    assert!(matches!(
        retry.outcome,
        WitnessOperationOutcomeV1::Prepare(boxed)
            if matches!(*boxed, WitnessPrepareOutcomeV1::AlreadyPrepared(_))
    ));
    assert_eq!(&fixture.proxy.events()[before_retry..], &["read"]);
    assert_eq!(
        fixture.proxy.cas_attempted.load(Ordering::SeqCst),
        attempted
    );
    assert_eq!(fixture.proxy.cas_applied.load(Ordering::SeqCst), applied);

    let different = fixture.candidate_with_larger_state()?;
    let different_request = fixture.prepare_request_for_candidate(&different)?;
    let before_conflict = fixture.proxy.events().len();
    let WitnessServiceResponseV1::Outcome(conflict) = fixture
        .dispatch_request(&dispatcher, &different_request)
        .await?
    else {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    };
    assert!(matches!(
        conflict.outcome,
        WitnessOperationOutcomeV1::Prepare(boxed)
            if matches!(*boxed, WitnessPrepareOutcomeV1::Conflict)
    ));
    assert_eq!(&fixture.proxy.events()[before_conflict..], &["read"]);
    assert_eq!(
        fixture.proxy.cas_attempted.load(Ordering::SeqCst),
        attempted
    );
    assert_eq!(fixture.proxy.cas_applied.load(Ordering::SeqCst), applied);

    let mut invalid_conflict = different_request.clone();
    let WitnessServiceRequestBodyV1::Prepare { candidate, .. } = &mut invalid_conflict.body else {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    };
    candidate.preimage.state_attestation.signature_hex = "0".repeat(128);
    rebind_outer_request(
        &mut invalid_conflict,
        &fixture.ephemeral,
        &fixture.session,
        WitnessOperationV1::Prepare,
        &different.txid,
    )?;
    let before_mixed = fixture.proxy.events().len();
    assert_signed_application_failure(
        &fixture,
        &dispatcher,
        &invalid_conflict,
        WitnessServiceFailureCodeV1::InvalidSignature,
    )
    .await?;
    assert_eq!(&fixture.proxy.events()[before_mixed..], &["read"]);
    assert_eq!(
        fixture.proxy.cas_attempted.load(Ordering::SeqCst),
        attempted
    );
    assert_eq!(fixture.proxy.cas_applied.load(Ordering::SeqCst), applied);

    let mut invalid_retry = request.clone();
    invalid_retry
        .authorization
        .as_mut()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .signature
        .signature_hex = "0".repeat(128);
    let before_invalid = fixture.proxy.events().len();
    assert_signed_application_failure(
        &fixture,
        &dispatcher,
        &invalid_retry,
        WitnessServiceFailureCodeV1::InvalidSignature,
    )
    .await?;
    assert_eq!(&fixture.proxy.events()[before_invalid..], &["read"]);
    assert_eq!(
        fixture.proxy.cas_attempted.load(Ordering::SeqCst),
        attempted
    );
    assert_eq!(fixture.proxy.cas_applied.load(Ordering::SeqCst), applied);

    for (same_winner, expected_already) in [(true, true), (false, false)] {
        let winner = Fixture::new(CasMode::Apply)?;
        let winner_dispatcher = winner.dispatcher().await.map_err(dispatch_error)?;
        let winner_request = winner.prepare_request()?;
        let observed_candidate = if same_winner {
            winner.candidate.clone()
        } else {
            winner.candidate_with_larger_state()?
        };
        let observed = winner.envelope_with_prepared_candidate(&observed_candidate)?;
        let observed_revision =
            winner
                .store_snapshot()
                .0
                .checked_add(1)
                .ok_or(ProtocolError::Overflow {
                    counter: "observed_revision",
                })?;
        winner.set_conflict_observed(observed_revision, observed);
        let WitnessServiceResponseV1::Outcome(response) = winner
            .dispatch_request(&winner_dispatcher, &winner_request)
            .await?
        else {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        };
        assert_eq!(
            matches!(
                &response.outcome,
                WitnessOperationOutcomeV1::Prepare(boxed)
                    if matches!(boxed.as_ref(), WitnessPrepareOutcomeV1::AlreadyPrepared(_))
            ),
            expected_already
        );
        assert_eq!(
            matches!(
                &response.outcome,
                WitnessOperationOutcomeV1::Prepare(boxed)
                    if matches!(boxed.as_ref(), WitnessPrepareOutcomeV1::Conflict)
            ),
            !expected_already
        );
        assert_eq!(winner.proxy.events(), vec!["read", "cas"]);
        assert_eq!(winner.proxy.cas_attempted.load(Ordering::SeqCst), 1);
        assert_eq!(winner.proxy.cas_applied.load(Ordering::SeqCst), 0);
    }

    let lost = Fixture::new(CasMode::Apply)?;
    let lost_dispatcher = lost.dispatcher().await.map_err(dispatch_error)?;
    let original = lost.prepare_request()?;
    lost.set_cas_mode(CasMode::ApplyThenUnavailable);
    assert!(matches!(
        lost_dispatcher
            .dispatch(
                PublicWitnessServiceConfigV1::subject_for(original.operation),
                &original.canonical_bytes()?,
            )
            .await,
        Err(PublicWitnessDispatchErrorV1::OutcomeUnknown)
    ));
    let lost_attempted = lost.proxy.cas_attempted.load(Ordering::SeqCst);
    let lost_applied = lost.proxy.cas_applied.load(Ordering::SeqCst);
    let replay_start = lost.proxy.events().len();
    lost.set_cas_mode(CasMode::Apply);
    let WitnessServiceResponseV1::Outcome(recovered) =
        lost.dispatch_request(&lost_dispatcher, &original).await?
    else {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    };
    assert!(matches!(
        recovered.outcome,
        WitnessOperationOutcomeV1::Prepare(boxed)
            if matches!(*boxed, WitnessPrepareOutcomeV1::AlreadyPrepared(_))
    ));
    assert_eq!(&lost.proxy.events()[replay_start..], &["read"]);
    assert_eq!(
        lost.proxy.cas_attempted.load(Ordering::SeqCst),
        lost_attempted
    );
    assert_eq!(lost.proxy.cas_applied.load(Ordering::SeqCst), lost_applied);
    Ok(())
}

async fn assert_lost_response_remains_unknown(operation: OperationCase) -> ProtocolResult<()> {
    let fixture = Fixture::new(CasMode::Apply)?;
    let dispatcher = fixture.dispatcher().await.map_err(dispatch_error)?;
    let request = operation_request(&fixture, &dispatcher, operation).await?;
    fixture.set_cas_mode(CasMode::ApplyThenUnavailable);
    let before = fixture.proxy.events().len();
    let before_attempted = fixture.proxy.cas_attempted.load(Ordering::SeqCst);
    let before_applied = fixture.proxy.cas_applied.load(Ordering::SeqCst);
    assert!(matches!(
        dispatcher
            .dispatch(
                PublicWitnessServiceConfigV1::subject_for(request.operation),
                &request.canonical_bytes()?,
            )
            .await,
        Err(PublicWitnessDispatchErrorV1::OutcomeUnknown)
    ));
    assert_eq!(&fixture.proxy.events()[before..], &["read", "cas", "read"]);
    assert_eq!(
        fixture.proxy.cas_attempted.load(Ordering::SeqCst),
        before_attempted + 1
    );
    assert_eq!(
        fixture.proxy.cas_applied.load(Ordering::SeqCst),
        before_applied + 1
    );
    Ok(())
}

async fn assert_post_cas_acknowledgements_remain_unknown() -> ProtocolResult<()> {
    for (label, mode, confirmation_attempted) in [
        ("malformed", CasMode::AckMalformed, false),
        ("duplicate", CasMode::AckDuplicate, false),
        ("lower", CasMode::AckLower, false),
        ("wrong_kind", CasMode::AckWrongKind, false),
        ("wrong_stream", CasMode::AckWrongStream, false),
        (
            "wrong_previous_revision",
            CasMode::AckWrongPreviousRevision,
            false,
        ),
        ("wrong_new_revision", CasMode::AckWrongNewRevision, true),
        ("wrong_digest", CasMode::AckWrongDigest, false),
        (
            "wrong_request_digest",
            CasMode::AckWrongRequestDigest,
            false,
        ),
        ("unknown", CasMode::AckUnknown, false),
        (
            "wrong_value",
            CasMode::ApplyThenConfirmationSubstitute,
            true,
        ),
    ] {
        let fixture = Fixture::new(CasMode::Apply)?;
        let dispatcher = fixture.dispatcher().await.map_err(dispatch_error)?;
        let request = fixture.establish_request()?;
        if mode == CasMode::ApplyThenConfirmationSubstitute {
            fixture.set_confirmation_observed(fixture.store_snapshot().1);
        } else {
            fixture.set_cas_mode(mode);
        }
        assert!(
            matches!(
                dispatcher
                    .dispatch(
                        PublicWitnessServiceConfigV1::subject_for(request.operation),
                        &request.canonical_bytes()?,
                    )
                    .await,
                Err(PublicWitnessDispatchErrorV1::OutcomeUnknown)
            ),
            "post-CAS acknowledgement unexpectedly became deterministic: {label}"
        );
        assert_eq!(
            fixture.proxy.events(),
            if confirmation_attempted {
                vec!["read", "cas", "read"]
            } else {
                vec!["read", "cas"]
            },
            "post-CAS call sequence differs: {label}"
        );
        assert_eq!(fixture.proxy.cas_attempted.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.proxy.cas_applied.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

async fn assert_cross_operation_winners() -> ProtocolResult<()> {
    let abort_wins = Fixture::new(CasMode::Apply)?;
    let abort_dispatcher = abort_wins.dispatcher().await.map_err(dispatch_error)?;
    let prepare = abort_wins.prepare_request()?;
    assert!(matches!(
        abort_wins
            .dispatch_request(&abort_dispatcher, &prepare)
            .await?,
        WitnessServiceResponseV1::Outcome(_)
    ));
    let abort = abort_wins.abort_request()?;
    assert!(matches!(
        abort_wins
            .dispatch_request(&abort_dispatcher, &abort)
            .await?,
        WitnessServiceResponseV1::Outcome(_)
    ));
    let commit = abort_wins.commit_request()?;
    let WitnessServiceResponseV1::Outcome(commit_attestation) = abort_wins
        .dispatch_request(&abort_dispatcher, &commit)
        .await?
    else {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    };
    assert!(matches!(
        commit_attestation.outcome,
        WitnessOperationOutcomeV1::Commit(boxed)
            if matches!(*boxed, WitnessCommitOutcomeV1::GenesisAborted(_))
    ));

    let commit_wins = Fixture::new(CasMode::Apply)?;
    let commit_dispatcher = commit_wins.dispatcher().await.map_err(dispatch_error)?;
    let prepare = commit_wins.prepare_request()?;
    assert!(matches!(
        commit_wins
            .dispatch_request(&commit_dispatcher, &prepare)
            .await?,
        WitnessServiceResponseV1::Outcome(_)
    ));
    let commit = commit_wins.commit_request()?;
    assert!(matches!(
        commit_wins
            .dispatch_request(&commit_dispatcher, &commit)
            .await?,
        WitnessServiceResponseV1::Outcome(_)
    ));
    let abort = commit_wins.abort_request()?;
    let WitnessServiceResponseV1::Outcome(abort_attestation) = commit_wins
        .dispatch_request(&commit_dispatcher, &abort)
        .await?
    else {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    };
    assert!(matches!(
        abort_attestation.outcome,
        WitnessOperationOutcomeV1::Abort(boxed)
            if matches!(*boxed, WitnessAbortOutcomeV1::Committed(_))
    ));

    let target = Fixture::new(CasMode::Apply)?;
    let target_dispatcher = target.dispatcher().await.map_err(dispatch_error)?;
    let competitor = Fixture::new(CasMode::Apply)?;
    let competitor_dispatcher = competitor.dispatcher().await.map_err(dispatch_error)?;
    for (fixture, dispatcher) in [
        (&target, &target_dispatcher),
        (&competitor, &competitor_dispatcher),
    ] {
        let prepare = fixture.prepare_request()?;
        fixture.dispatch_request(dispatcher, &prepare).await?;
    }
    competitor
        .dispatch_request(&competitor_dispatcher, &competitor.abort_request()?)
        .await?;
    let (revision, envelope) = competitor.store_snapshot();
    target.set_conflict_observed(revision, envelope);
    let WitnessServiceResponseV1::Outcome(attestation) = target
        .dispatch_request(&target_dispatcher, &target.commit_request()?)
        .await?
    else {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    };
    assert!(matches!(
        attestation.outcome,
        WitnessOperationOutcomeV1::Commit(boxed)
            if matches!(*boxed, WitnessCommitOutcomeV1::GenesisAborted(_))
    ));

    let target = Fixture::new(CasMode::Apply)?;
    let target_dispatcher = target.dispatcher().await.map_err(dispatch_error)?;
    let competitor = Fixture::new(CasMode::Apply)?;
    let competitor_dispatcher = competitor.dispatcher().await.map_err(dispatch_error)?;
    for (fixture, dispatcher) in [
        (&target, &target_dispatcher),
        (&competitor, &competitor_dispatcher),
    ] {
        fixture
            .dispatch_request(dispatcher, &fixture.prepare_request()?)
            .await?;
    }
    competitor
        .dispatch_request(&competitor_dispatcher, &competitor.commit_request()?)
        .await?;
    let (revision, envelope) = competitor.store_snapshot();
    target.set_conflict_observed(revision, envelope);
    let WitnessServiceResponseV1::Outcome(attestation) = target
        .dispatch_request(&target_dispatcher, &target.abort_request()?)
        .await?
    else {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    };
    assert!(matches!(
        attestation.outcome,
        WitnessOperationOutcomeV1::Abort(boxed)
            if matches!(*boxed, WitnessAbortOutcomeV1::Committed(_))
    ));

    for operation in [
        WitnessServiceOperationV1::Commit,
        WitnessServiceOperationV1::Abort,
    ] {
        let before = target.proxy.events().len();
        let expected_store_digest = target.store_snapshot().1.store_state_digest()?;
        let unrelated_txid = "f".repeat(64);
        let unrelated = target.session_request_for_txid(
            operation,
            if operation == WitnessServiceOperationV1::Commit {
                WitnessOperationV1::Commit
            } else {
                WitnessOperationV1::Abort
            },
            if operation == WitnessServiceOperationV1::Commit {
                WitnessServiceRequestBodyV1::Commit {
                    session: Box::new(target.session.clone()),
                    txid: unrelated_txid.clone(),
                }
            } else {
                WitnessServiceRequestBodyV1::Abort {
                    session: Box::new(target.session.clone()),
                    txid: unrelated_txid.clone(),
                }
            },
            &unrelated_txid,
        )?;
        let WitnessServiceResponseV1::Failure(failure) = target
            .dispatch_request(&target_dispatcher, &unrelated)
            .await?
        else {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        };
        assert_eq!(
            failure.failure_code,
            WitnessServiceFailureCodeV1::StaleIntent
        );
        assert_eq!(
            failure.store_state_digest.as_deref(),
            Some(expected_store_digest.as_str())
        );
        assert_eq!(&target.proxy.events()[before..], &["read"]);
    }
    Ok(())
}

async fn assert_genesis_abort_successor_after_restart() -> ProtocolResult<()> {
    let fixture = Fixture::new(CasMode::Apply)?;
    let first_dispatcher = fixture.dispatcher().await.map_err(dispatch_error)?;
    assert!(matches!(
        fixture
            .dispatch_request(&first_dispatcher, &fixture.prepare_request()?)
            .await?,
        WitnessServiceResponseV1::Outcome(_)
    ));
    assert!(matches!(
        fixture
            .dispatch_request(&first_dispatcher, &fixture.abort_request()?)
            .await?,
        WitnessServiceResponseV1::Outcome(_)
    ));
    let (_, aborted_envelope) = fixture.store_snapshot();
    let aborted = aborted_envelope
        .genesis_abort
        .clone()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    assert!(aborted_envelope.prepared.is_none());
    drop(first_dispatcher);

    // Reconstructing the dispatcher proves the successor authority comes
    // from the persisted authenticated envelope, not the prior Abort reply.
    let restarted_dispatcher = fixture.dispatcher().await.map_err(dispatch_error)?;
    let next_intent = aborted
        .intent_counter
        .checked_add(1)
        .ok_or(ProtocolError::Overflow {
            counter: "intent_counter",
        })?;
    for invalid_intent in [
        aborted.intent_counter,
        next_intent.checked_add(1).ok_or(ProtocolError::Overflow {
            counter: "intent_counter",
        })?,
    ] {
        let stale_candidate = fixture.candidate_for_intent(invalid_intent)?;
        let stale_request = fixture.prepare_request_for_candidate(&stale_candidate)?;
        assert_signed_application_failure(
            &fixture,
            &restarted_dispatcher,
            &stale_request,
            WitnessServiceFailureCodeV1::StaleIntent,
        )
        .await?;
        assert_eq!(fixture.proxy.events(), vec!["read"]);
        fixture.proxy.reset_observations();
    }
    let next_candidate = fixture.candidate_for_intent(next_intent)?;
    let next_request = fixture.prepare_request_for_candidate(&next_candidate)?;
    let admission_entry = fixture
        .admission_set
        .entries
        .iter()
        .find(|entry| entry.stream_id == fixture.admission.stream_id)
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    let stream_initialization_digest = aborted_envelope.stream_initialization_digest.clone();
    assert!(matches!(
        verify_public_prepare(
            admission_entry,
            &aborted_envelope.bucket_epoch_digest,
            &stream_initialization_digest,
            &aborted_envelope,
            &next_request,
            &fixture.witness,
        ),
        WitnessPrepareVerificationV1::New(_)
    ));

    let mut wrong_session_request = next_request.clone();
    let WitnessServiceRequestBodyV1::Prepare { session, .. } = &mut wrong_session_request.body
    else {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    };
    session.session_commitment = "e".repeat(64);
    let wrong_session = session.as_ref().clone();
    rebind_outer_request(
        &mut wrong_session_request,
        &fixture.ephemeral,
        &wrong_session,
        WitnessOperationV1::Prepare,
        &next_candidate.txid,
    )?;
    assert!(matches!(
        verify_public_prepare(
            admission_entry,
            &aborted_envelope.bucket_epoch_digest,
            &stream_initialization_digest,
            &aborted_envelope,
            &wrong_session_request,
            &fixture.witness,
        ),
        WitnessPrepareVerificationV1::Rejected(_)
    ));
    let foreign_witness = Ed25519Signer::from_secret_material("phase285-plan04-foreign-proof");
    assert!(matches!(
        verify_public_prepare(
            admission_entry,
            &aborted_envelope.bucket_epoch_digest,
            &stream_initialization_digest,
            &aborted_envelope,
            &next_request,
            &foreign_witness,
        ),
        WitnessPrepareVerificationV1::Rejected(_)
    ));
    let mut corrupt_envelope = aborted_envelope.clone();
    corrupt_envelope.signature.signature_hex = "0".repeat(128);
    assert!(matches!(
        verify_public_prepare(
            admission_entry,
            &aborted_envelope.bucket_epoch_digest,
            &stream_initialization_digest,
            &corrupt_envelope,
            &next_request,
            &fixture.witness,
        ),
        WitnessPrepareVerificationV1::Rejected(_)
    ));
    for (bucket_epoch, initialization) in [
        ("f".repeat(64), stream_initialization_digest.clone()),
        (aborted_envelope.bucket_epoch_digest.clone(), "f".repeat(64)),
    ] {
        assert!(matches!(
            verify_public_prepare(
                admission_entry,
                &bucket_epoch,
                &initialization,
                &aborted_envelope,
                &next_request,
                &fixture.witness,
            ),
            WitnessPrepareVerificationV1::Rejected(_)
        ));
    }

    let WitnessServiceResponseV1::Outcome(prepared_attestation) = fixture
        .dispatch_request(&restarted_dispatcher, &next_request)
        .await?
    else {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    };
    assert!(matches!(
        prepared_attestation.outcome,
        WitnessOperationOutcomeV1::Prepare(boxed)
            if matches!(*boxed, WitnessPrepareOutcomeV1::Prepared(_))
    ));
    assert_eq!(fixture.proxy.events(), vec!["read", "cas", "read"]);
    let (_, confirmed) = fixture.store_snapshot();
    assert!(confirmed.genesis_abort.is_none());
    assert_eq!(
        confirmed
            .prepared
            .as_ref()
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?
            .prepared
            .genesis_abort
            .as_ref(),
        Some(&aborted)
    );
    assert_eq!(
        confirmed
            .prepared
            .as_ref()
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?
            .prepared
            .head
            .intent_counter,
        next_intent
    );
    Ok(())
}

async fn assert_typed_conflict(operation: OperationCase) -> ProtocolResult<()> {
    let fixture = Fixture::new(CasMode::Apply)?;
    let dispatcher = fixture.dispatcher().await.map_err(dispatch_error)?;
    let request = operation_request(&fixture, &dispatcher, operation).await?;
    fixture.set_cas_mode(CasMode::Conflict);
    let before = fixture.proxy.events().len();
    let WitnessServiceResponseV1::Failure(failure) =
        fixture.dispatch_request(&dispatcher, &request).await?
    else {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    };
    assert_eq!(failure.failure_code, WitnessServiceFailureCodeV1::Conflict);
    assert_eq!(&fixture.proxy.events()[before..], &["read", "cas"]);
    Ok(())
}

async fn assert_stale_reads_after_rotations(rotations: usize) -> ProtocolResult<()> {
    let fixture = Fixture::new(CasMode::Apply)?;
    fixture.rotate_current_session(rotations)?;
    let dispatcher = fixture.dispatcher().await.map_err(dispatch_error)?;
    let requests = [
        fixture.read_prepared_request()?,
        fixture.read_head_request()?,
        fixture.fetch_payload_request()?,
    ];
    for request in requests {
        let WitnessServiceResponseV1::Failure(failure) =
            fixture.dispatch_request(&dispatcher, &request).await?
        else {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        };
        assert_eq!(
            failure.failure_code,
            WitnessServiceFailureCodeV1::StaleSession
        );
    }
    assert_eq!(fixture.proxy.events(), vec!["read", "read", "read"]);
    Ok(())
}

async fn assert_stale_rotation_failure_is_signed() -> ProtocolResult<()> {
    let fixture = Fixture::new(CasMode::Apply)?;
    let stale_request = fixture.establish_request()?;
    fixture.rotate_current_session(1)?;
    let expected_store_digest = fixture
        .proxy
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .envelope
        .store_state_digest()?;
    let dispatcher = fixture.dispatcher().await.map_err(dispatch_error)?;
    let WitnessServiceResponseV1::Failure(failure) = fixture
        .dispatch_request(&dispatcher, &stale_request)
        .await?
    else {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    };
    assert_eq!(
        failure.failure_code,
        WitnessServiceFailureCodeV1::StaleRotationFence
    );
    assert_eq!(
        failure.store_state_digest.as_deref(),
        Some(expected_store_digest.as_str())
    );
    failure.validate()?;
    assert_eq!(fixture.proxy.events(), vec!["read"]);
    Ok(())
}

async fn assert_signed_application_failure(
    fixture: &Fixture,
    dispatcher: &PublicWitnessDispatcher<RecordingProxy>,
    request: &WitnessServiceRequestV1,
    expected: WitnessServiceFailureCodeV1,
) -> ProtocolResult<()> {
    let expected_store_digest = fixture.store_snapshot().1.store_state_digest()?;
    let WitnessServiceResponseV1::Failure(failure) = fixture
        .dispatch_outer_valid_request(dispatcher, request)
        .await?
    else {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    };
    assert_eq!(failure.failure_code, expected);
    assert_eq!(
        failure.store_state_digest.as_deref(),
        Some(expected_store_digest.as_str())
    );
    failure.validate()
}

async fn assert_complete_signed_application_failures() -> ProtocolResult<()> {
    let invalid_authorization = Fixture::new(CasMode::Apply)?;
    let dispatcher = invalid_authorization
        .dispatcher()
        .await
        .map_err(dispatch_error)?;
    let mut request = invalid_authorization.prepare_request()?;
    request
        .authorization
        .as_mut()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .signature
        .signature_hex = "0".repeat(128);
    assert_signed_application_failure(
        &invalid_authorization,
        &dispatcher,
        &request,
        WitnessServiceFailureCodeV1::InvalidSignature,
    )
    .await?;
    assert_eq!(invalid_authorization.proxy.events(), vec!["read"]);

    let verifier_only = Fixture::new_with_initial_intent(CasMode::Apply, 2)?;
    let dispatcher = verifier_only.dispatcher().await.map_err(dispatch_error)?;
    let request = verifier_only.prepare_request()?;
    request.validate()?;
    assert_signed_application_failure(
        &verifier_only,
        &dispatcher,
        &request,
        WitnessServiceFailureCodeV1::StaleIntent,
    )
    .await?;
    assert_eq!(verifier_only.proxy.events(), vec!["read"]);

    let bounds = Fixture::new(CasMode::Apply)?;
    let dispatcher = bounds.dispatcher().await.map_err(dispatch_error)?;
    let mut request = bounds.prepare_request()?;
    let WitnessServiceRequestBodyV1::Prepare { candidate, .. } = &mut request.body else {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    };
    candidate
        .preimage
        .publication_binding
        .limits
        .max_payload_bytes = 1;
    rebind_outer_request(
        &mut request,
        &bounds.ephemeral,
        &bounds.session,
        WitnessOperationV1::Prepare,
        &bounds.candidate.txid,
    )?;
    assert_signed_application_failure(
        &bounds,
        &dispatcher,
        &request,
        WitnessServiceFailureCodeV1::BoundsExceeded,
    )
    .await?;
    assert_eq!(bounds.proxy.events(), vec!["read"]);

    for operation in [
        WitnessServiceOperationV1::Establish,
        WitnessServiceOperationV1::Discover,
    ] {
        let invalid_rotation = Fixture::new(CasMode::Apply)?;
        let dispatcher = invalid_rotation
            .dispatcher()
            .await
            .map_err(dispatch_error)?;
        let mut request = if operation == WitnessServiceOperationV1::Establish {
            invalid_rotation.establish_request()?
        } else {
            invalid_rotation.discover_request()?
        };
        match &mut request.body {
            WitnessServiceRequestBodyV1::Establish { challenge, .. }
            | WitnessServiceRequestBodyV1::Discover { challenge } => {
                challenge.signature.signature_hex = "0".repeat(128);
            }
            _ => return Err(ProtocolError::WitnessOutcomeMismatch),
        }
        rebind_outer_identity(&mut request)?;
        assert_signed_application_failure(
            &invalid_rotation,
            &dispatcher,
            &request,
            WitnessServiceFailureCodeV1::InvalidSignature,
        )
        .await?;
        assert_eq!(invalid_rotation.proxy.events(), vec!["read"]);
    }

    let expected_head = Fixture::new(CasMode::Apply)?;
    let dispatcher = expected_head.dispatcher().await.map_err(dispatch_error)?;
    expected_head
        .dispatch_request(&dispatcher, &expected_head.prepare_request()?)
        .await?;
    expected_head
        .dispatch_request(&dispatcher, &expected_head.commit_request()?)
        .await?;
    expected_head.proxy.reset_observations();
    assert_signed_application_failure(
        &expected_head,
        &dispatcher,
        &expected_head.prepare_request()?,
        WitnessServiceFailureCodeV1::ExpectedHeadMismatch,
    )
    .await?;
    assert_eq!(expected_head.proxy.events(), vec!["read"]);

    let exhausted = Fixture::new(CasMode::Apply)?;
    exhausted.exhaust_current_session_generation()?;
    let dispatcher = exhausted.dispatcher().await.map_err(dispatch_error)?;
    assert_signed_application_failure(
        &exhausted,
        &dispatcher,
        &exhausted.establish_request()?,
        WitnessServiceFailureCodeV1::BoundsExceeded,
    )
    .await?;
    assert_eq!(exhausted.proxy.events(), vec!["read"]);
    Ok(())
}

struct Fixture {
    governance: Ed25519Signer,
    witness: Ed25519Signer,
    ephemeral: Ed25519Signer,
    binding: PublicationBindingV1,
    admission: WitnessAdmissionRecordV1,
    fence_request: WitnessSessionFenceRequestV1,
    session: WitnessSessionV1,
    candidate: CandidateV1,
    proxy: RecordingProxy,
    bucket_configuration_digest: String,
    admission_set: WitnessAdmissionSetV1,
}

struct SecondaryStreamFixture {
    fence_request: WitnessServiceRequestV1,
    prepare_request: WitnessServiceRequestV1,
}

impl Fixture {
    fn new(cas_mode: CasMode) -> ProtocolResult<Self> {
        Self::new_with_initial_intent(cas_mode, 1)
    }

    fn new_with_initial_intent(
        cas_mode: CasMode,
        initial_intent_counter: u64,
    ) -> ProtocolResult<Self> {
        Self::new_with_initial_values(cas_mode, 0, 0, initial_intent_counter)
    }

    fn new_with_initial_values(
        cas_mode: CasMode,
        initial_epoch: u64,
        initial_sequence: u64,
        initial_intent_counter: u64,
    ) -> ProtocolResult<Self> {
        let governance = Ed25519Signer::from_secret_material("phase285-plan04-governance");
        let witness = Ed25519Signer::from_secret_material("phase285-plan04-witness");
        let ephemeral = Ed25519Signer::from_secret_material("phase285-plan04-ephemeral");
        let binding = binding(&governance, &witness)?;
        let mut admission = admission(&binding)?;
        admission.initial_epoch = initial_epoch;
        admission.initial_sequence = initial_sequence;
        admission.initial_intent_counter = initial_intent_counter;
        admission.admission_digest = admission.computed_digest()?;
        admission.validate()?;
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
            request: fence_request.clone(),
            admission_digest: admission.admission_digest.clone(),
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
            fence_request.request_digest()?,
            &challenge,
            session.clone(),
            None,
        )?;
        let mut envelope = empty;
        envelope.session = Some(session.clone());
        envelope.last_session_rotation = Some(receipt);
        envelope.store_generation = 1;
        envelope.signature = witness.sign(&envelope.signing_bytes()?);
        envelope.validate()?;
        let candidate = candidate(&governance, &binding)?.build()?;
        let bucket_configuration_digest = "c".repeat(64);
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
        let admission_set_digest = admission_set.admission_set_digest.clone();
        let stream_key = witness_stream_key(&admission.stream_id)?;
        let mut initialized_streams = BTreeMap::new();
        initialized_streams.insert(
            stream_key.clone(),
            WitnessStreamInitializationRecordV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                stream_initialization_digest: envelope.stream_initialization_digest.clone(),
                empty_envelope_digest: "d".repeat(64),
            },
        );
        let mut ready_manifest = WitnessBucketManifestV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            bucket_epoch_digest: envelope.bucket_epoch_digest.clone(),
            bucket_configuration_digest: bucket_configuration_digest.clone(),
            admission_set_digest: admission_set_digest.clone(),
            stream_keys: vec![stream_key],
            initialized_streams,
            phase: WitnessBucketManifestPhaseV1::Ready,
            witness_identity: binding.witness_identity.clone(),
            witness_key_id: witness.key_id().to_string(),
            signature: witness.sign(&[]),
        };
        ready_manifest.signature = witness.sign(&ready_manifest.signing_bytes()?);
        ready_manifest.validate()?;
        let expected_epoch_digest = envelope.bucket_epoch_digest.clone();
        let proxy = RecordingProxy {
            calls: Arc::new(AtomicUsize::new(0)),
            cas_attempted: Arc::new(AtomicUsize::new(0)),
            cas_applied: Arc::new(AtomicUsize::new(0)),
            inspect_calls: Arc::new(AtomicUsize::new(0)),
            ready_valid_responses: Arc::new(AtomicUsize::new(0)),
            state: Arc::new(Mutex::new(ProxyState {
                revision: 7,
                envelope,
                events: Vec::new(),
            })),
            secondary_state: Arc::new(Mutex::new(None)),
            entered: Arc::new(Notify::new()),
            release: Arc::new(Mutex::new(None)),
            cas_mode: Arc::new(Mutex::new(cas_mode)),
            conflict_observed: Arc::new(Mutex::new(None)),
            confirmation_observed: Arc::new(Mutex::new(None)),
            ready_manifest: Arc::new(Mutex::new(ready_manifest)),
            ready_mutation: Arc::new(Mutex::new(ReadyMutation::None)),
            ready_signer: witness.clone(),
            foreign_ready_signer: Ed25519Signer::from_secret_material(
                "phase285-plan04-foreign-ready",
            ),
            expected_admission_digest: admission.admission_digest.clone(),
            expected_epoch_digest,
            expected_anchor_digest: "4".repeat(64),
        };
        Ok(Self {
            governance,
            witness,
            ephemeral,
            binding,
            admission,
            fence_request,
            session,
            candidate,
            proxy,
            bucket_configuration_digest,
            admission_set,
        })
    }

    fn config(&self) -> ProtocolResult<PublicWitnessServiceConfigV1> {
        let state = self
            .proxy
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(PublicWitnessServiceConfigV1 {
            nats_url: "tls://127.0.0.1:4222".to_string(),
            nats_credentials_path: "/conf/runtime.creds".to_string(),
            tls_ca_path: "/conf/ca.pem".to_string(),
            tls_server_name: "nats.phase285.test".to_string(),
            witness_key_path: "/conf/witness.key".to_string(),
            witness_identity: self.witness_identity().to_string(),
            witness_key_id: self.witness.key_id().to_string(),
            bucket_name: "phase285".to_string(),
            bucket_configuration_digest: self.bucket_configuration_digest.clone(),
            bucket_epoch_digest: state.envelope.bucket_epoch_digest.clone(),
            bucket_anchor_digest: "4".repeat(64),
            admission_set_digest: self.admission_set.admission_set_digest.clone(),
            ready_manifest_digest: self
                .proxy
                .ready_manifest
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .digest()?,
            admission_set: self.admission_set.clone(),
            max_request_bytes: 1_048_576,
            max_response_bytes: 1_048_576,
            ingress_queue_capacity: 1,
            max_in_flight: 1,
            request_deadline_millis: 1_000,
        })
    }

    fn configure_primary_entry<F>(&mut self, configure: F) -> ProtocolResult<()>
    where
        F: FnOnce(&mut WitnessAdmissionEntryV1),
    {
        let previous_admission_digest = self.admission.admission_digest.clone();
        let updated_entry = {
            let entry = self
                .admission_set
                .entries
                .iter_mut()
                .find(|entry| entry.stream_id == self.admission.stream_id)
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
            configure(entry);
            entry.admission.admission_digest = entry.admission.computed_digest()?;
            entry.validate()?;
            entry.clone()
        };
        self.admission = updated_entry.admission.clone();
        self.admission_set.admission_set_digest = self.admission_set.computed_digest()?;
        self.admission_set.validate()?;
        let mut initialization_digest = None;
        if self.admission.admission_digest != previous_admission_digest {
            let mut state = self
                .proxy
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.envelope.admission_digest = self.admission.admission_digest.clone();
            let digest = WitnessStreamInitializationV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                bucket_epoch_digest: state.envelope.bucket_epoch_digest.clone(),
                admission_digest: self.admission.admission_digest.clone(),
                stream_id: self.admission.stream_id.clone(),
                witness_identity: self.admission.witness_identity.clone(),
                witness_key_id: self.admission.witness_key_id.clone(),
            }
            .digest()?;
            state.envelope.stream_initialization_digest = digest.clone();
            state.envelope.signature = self.witness.sign(&state.envelope.signing_bytes()?);
            state.envelope.validate()?;
            initialization_digest = Some(digest);
            self.proxy.expected_admission_digest = self.admission.admission_digest.clone();
        }
        let mut manifest = self
            .proxy
            .ready_manifest
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        manifest.admission_set_digest = self.admission_set.admission_set_digest.clone();
        if let Some(initialization_digest) = initialization_digest {
            let stream_key = witness_stream_key(&self.admission.stream_id)?;
            manifest
                .initialized_streams
                .get_mut(&stream_key)
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?
                .stream_initialization_digest = initialization_digest;
        }
        manifest.signature = self.witness.sign(&manifest.signing_bytes()?);
        manifest.validate()
    }

    fn candidate_with_larger_state(&self) -> ProtocolResult<CandidateV1> {
        let mut preimage = candidate(&self.governance, &self.binding)?;
        let state_payload = br#"{"state":11}"#.to_vec();
        let state_digest = sha256_hex(&state_payload);
        preimage.state_byte_len = state_payload.len() as u64;
        preimage.state_digest = state_digest.clone();
        preimage.state_attestation = sign_payload(
            &self.governance,
            STATE_PAYLOAD_DOMAIN_V1,
            &self.binding,
            state_payload.clone(),
            state_digest,
        )?;
        preimage.state_payload = state_payload;
        preimage.build()
    }

    fn candidate_with_larger_checkpoint(&self) -> ProtocolResult<CandidateV1> {
        let mut preimage = candidate(&self.governance, &self.binding)?;
        let checkpoint_payload = br#"{"checkpoint":11}"#.to_vec();
        let checkpoint_digest = sha256_hex(&checkpoint_payload);
        preimage.checkpoint_byte_len = checkpoint_payload.len() as u64;
        preimage.checkpoint_digest = checkpoint_digest.clone();
        preimage.checkpoint_attestation = sign_payload(
            &self.governance,
            CHECKPOINT_PAYLOAD_DOMAIN_V1,
            &self.binding,
            checkpoint_payload.clone(),
            checkpoint_digest,
        )?;
        preimage.checkpoint_payload = checkpoint_payload;
        preimage.build()
    }

    fn envelope_with_prepared_candidate(
        &self,
        candidate: &CandidateV1,
    ) -> ProtocolResult<WitnessStoreEnvelopeV1> {
        let mut envelope = self.store_snapshot().1;
        let session_generation = envelope
            .session
            .as_ref()
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?
            .session_generation;
        envelope.prepared = Some(WitnessStoredPreparedV1 {
            candidate: candidate.preimage.clone(),
            prepared: WitnessPreparedV1::from_candidate(
                candidate,
                envelope.current.as_ref().map(|stored| stored.head.clone()),
                session_generation,
            )?,
        });
        envelope.genesis_abort = None;
        envelope.store_generation =
            envelope
                .store_generation
                .checked_add(1)
                .ok_or(ProtocolError::Overflow {
                    counter: "store_generation",
                })?;
        envelope.signature = self.witness.sign(&envelope.signing_bytes()?);
        envelope.validate()?;
        Ok(envelope)
    }

    fn enable_second_stream(&mut self) -> ProtocolResult<SecondaryStreamFixture> {
        self.enable_second_stream_with(|_| {})
    }

    fn enable_second_stream_with<F>(
        &mut self,
        configure: F,
    ) -> ProtocolResult<SecondaryStreamFixture>
    where
        F: FnOnce(&mut WitnessAdmissionEntryV1),
    {
        let governance = Ed25519Signer::from_secret_material("phase285-plan04-governance-two");
        let ephemeral = Ed25519Signer::from_secret_material("phase285-plan04-ephemeral-two");
        let mut binding = self.binding.clone();
        binding.stream_id = "uma-secondary".to_string();
        binding.generation = "a".repeat(64);
        binding.parent_directory = artifact(201);
        binding.pool_directory = artifact(202);
        binding.pool_lock = artifact(203);
        binding.binding_file = artifact(204);
        binding.authority_pair = AuthorityPairIdentityV1 {
            current: ArtifactIdentityV1 {
                device: 3,
                inode: 1,
            },
            legacy: ArtifactIdentityV1 {
                device: 3,
                inode: 1,
            },
        };
        binding.publication_roles = PublicationRoleIdentitiesV1 {
            state_canonical: artifact(211),
            state_staging: artifact(212),
            checkpoint_canonical: artifact(213),
            checkpoint_staging: artifact(214),
            journal_primary: artifact(215),
            journal_secondary: artifact(216),
        };
        binding.cleanup_slot_identities = (301..(301 + FIXED_CLEANUP_SLOT_COUNT as u64))
            .map(artifact)
            .collect();
        binding.signer_key_id = governance.key_id().to_string();
        binding.binding_digest = binding.computed_digest()?;
        binding.binding_signature = governance.sign(&binding.signing_bytes()?);
        binding.validate()?;
        let admission = admission(&binding)?;
        let mut admission_entry = WitnessAdmissionEntryV1 {
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
        configure(&mut admission_entry);
        admission_entry.admission.admission_digest = admission_entry.admission.computed_digest()?;
        admission_entry.validate()?;
        let admission = admission_entry.admission.clone();
        self.admission_set.entries.push(admission_entry);
        self.admission_set
            .entries
            .sort_by(|left, right| left.stream_id.cmp(&right.stream_id));
        self.admission_set.admission_set_digest = self.admission_set.computed_digest()?;
        self.admission_set.validate()?;

        let primary = self
            .proxy
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .envelope
            .clone();
        let initialization_digest = WitnessStreamInitializationV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            bucket_epoch_digest: primary.bucket_epoch_digest.clone(),
            admission_digest: admission.admission_digest.clone(),
            stream_id: admission.stream_id.clone(),
            witness_identity: admission.witness_identity.clone(),
            witness_key_id: admission.witness_key_id.clone(),
        }
        .digest()?;
        let mut envelope = WitnessStoreEnvelopeV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            admission_digest: admission.admission_digest.clone(),
            bucket_epoch_digest: primary.bucket_epoch_digest,
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
            signature: self.witness.sign(&[]),
        };
        envelope.signature = self.witness.sign(&envelope.signing_bytes()?);
        envelope.validate()?;
        *self
            .proxy
            .secondary_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(ProxyState {
            revision: 11,
            envelope: envelope.clone(),
            events: Vec::new(),
        });

        let stream_key = witness_stream_key(&admission.stream_id)?;
        let mut manifest = self
            .proxy
            .ready_manifest
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        manifest.admission_set_digest = self.admission_set.admission_set_digest.clone();
        manifest.stream_keys.push(stream_key.clone());
        manifest.stream_keys.sort();
        manifest.initialized_streams.insert(
            stream_key,
            WitnessStreamInitializationRecordV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                stream_initialization_digest: initialization_digest,
                empty_envelope_digest: "f".repeat(64),
            },
        );
        manifest.signature = self.witness.sign(&manifest.signing_bytes()?);
        manifest.validate()?;
        drop(manifest);

        let mut fence = WitnessSessionFenceRequestV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            stream_id: binding.stream_id.clone(),
            authority_pair: binding.authority_pair,
            binding_generation: binding.generation.clone(),
            binding_digest: binding.binding_digest.clone(),
            signer_key_id: binding.signer_key_id.clone(),
            witness_key_id: binding.witness_key_id.clone(),
            witness_identity: binding.witness_identity.clone(),
            requester_nonce: "c".repeat(64),
            signature: governance.sign(&[]),
        };
        fence.signature = governance.sign(&fence.signing_bytes()?);
        let fence_request = finalized_request(
            WitnessServiceOperationV1::Fence,
            admission.admission_digest.clone(),
            WitnessServiceRequestBodyV1::Fence {
                request: Box::new(fence.clone()),
            },
            None,
        )?;
        let mut state_fence = WitnessSessionStateFenceV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            request: fence.clone(),
            admission_digest: admission.admission_digest.clone(),
            bucket_epoch_digest: envelope.bucket_epoch_digest.clone(),
            bucket_anchor_digest: "4".repeat(64),
            ready_manifest_digest: self
                .proxy
                .ready_manifest
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .digest()?,
            store_state_digest: envelope.store_state_digest()?,
            current_session_generation: None,
            current_session_digest: None,
            current_head_digest: None,
            current_prepared_digest: None,
            witness_nonce: "d".repeat(64),
            witness_identity: binding.witness_identity.clone(),
            witness_key_id: binding.witness_key_id.clone(),
            signature: self.witness.sign(&[]),
        };
        state_fence.signature = self.witness.sign(&state_fence.signing_bytes()?);
        let mut challenge = RecoveryChallengeV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            stream_id: binding.stream_id.clone(),
            authority_pair: binding.authority_pair,
            binding_generation: binding.generation.clone(),
            binding_digest: binding.binding_digest.clone(),
            signer_key_id: binding.signer_key_id.clone(),
            witness_key_id: binding.witness_key_id.clone(),
            witness_identity: binding.witness_identity.clone(),
            state_fence,
            ephemeral_key_id: ephemeral.key_id().to_string(),
            nonce: "e".repeat(64),
            session_commitment: "f".repeat(64),
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
            session_generation: challenge.expected_session_generation()?,
            session_commitment: challenge.session_commitment.clone(),
        };
        session.validate()?;
        let receipt = WitnessSessionRotationReceiptV1::for_establish(
            fence.request_digest()?,
            &challenge,
            session.clone(),
            None,
        )?;
        {
            let mut secondary = self
                .proxy
                .secondary_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let state = secondary
                .as_mut()
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
            state.envelope.session = Some(session.clone());
            state.envelope.last_session_rotation = Some(receipt);
            state.envelope.store_generation = 1;
            state.envelope.signature = self.witness.sign(&state.envelope.signing_bytes()?);
            state.envelope.validate()?;
        }
        let candidate = candidate(&governance, &binding)?.build()?;
        let prepare_request = {
            let mut request = finalized_request(
                WitnessServiceOperationV1::Prepare,
                admission.admission_digest.clone(),
                WitnessServiceRequestBodyV1::Prepare {
                    session: Box::new(session.clone()),
                    expected_head: None,
                    candidate: Box::new(candidate.clone()),
                },
                None,
            )?;
            request.authorization = Some(authorization(
                &ephemeral,
                &session,
                WitnessOperationV1::Prepare,
                &candidate.txid,
                &request.request_digest,
            )?);
            request.validate()?;
            request
        };
        Ok(SecondaryStreamFixture {
            fence_request,
            prepare_request,
        })
    }

    fn secondary_events(&self) -> ProtocolResult<Vec<&'static str>> {
        self.proxy
            .secondary_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|state| state.events.clone())
            .ok_or(ProtocolError::WitnessOutcomeMismatch)
    }

    fn secondary_snapshot(&self) -> ProtocolResult<(u64, WitnessStoreEnvelopeV1)> {
        self.proxy
            .secondary_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|state| (state.revision, state.envelope.clone()))
            .ok_or(ProtocolError::WitnessOutcomeMismatch)
    }

    async fn dispatcher(
        &self,
    ) -> Result<PublicWitnessDispatcher<RecordingProxy>, PublicWitnessDispatchErrorV1> {
        let dispatcher = PublicWitnessDispatcher::new(
            self.config()
                .map_err(|_| PublicWitnessDispatchErrorV1::Invalid)?,
            self.witness.clone(),
            self.proxy.clone(),
        )
        .await?;
        self.proxy.reset_observations();
        Ok(dispatcher)
    }

    fn set_cas_mode(&self, mode: CasMode) {
        *self
            .proxy
            .cas_mode
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = mode;
    }

    fn set_conflict_observed(&self, revision: u64, envelope: WitnessStoreEnvelopeV1) {
        *self
            .proxy
            .conflict_observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((revision, envelope));
        self.set_cas_mode(CasMode::ConflictWinner);
    }

    fn set_confirmation_observed(&self, envelope: WitnessStoreEnvelopeV1) {
        *self
            .proxy
            .confirmation_observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(envelope);
        self.set_cas_mode(CasMode::ApplyThenConfirmationSubstitute);
    }

    fn store_snapshot(&self) -> (u64, WitnessStoreEnvelopeV1) {
        let state = self
            .proxy
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (state.revision, state.envelope.clone())
    }

    fn set_ready_mutation(&self, mutation: ReadyMutation) {
        *self
            .proxy
            .ready_mutation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = mutation;
    }

    fn mutate_manifest_admission(&self) -> ProtocolResult<()> {
        let mut manifest = self
            .proxy
            .ready_manifest
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        manifest.admission_set_digest = "e".repeat(64);
        manifest.signature = self.witness.sign(&manifest.signing_bytes()?);
        manifest.validate()
    }

    fn witness_identity(&self) -> &str {
        &self.binding.witness_identity
    }

    fn fence_request(&self) -> ProtocolResult<WitnessServiceRequestV1> {
        finalized_request(
            WitnessServiceOperationV1::Fence,
            self.admission.admission_digest.clone(),
            WitnessServiceRequestBodyV1::Fence {
                request: Box::new(self.fence_request.clone()),
            },
            None,
        )
    }

    fn prepare_request(&self) -> ProtocolResult<WitnessServiceRequestV1> {
        self.prepare_request_for_candidate(&self.candidate)
    }

    fn prepare_request_for_candidate(
        &self,
        candidate: &CandidateV1,
    ) -> ProtocolResult<WitnessServiceRequestV1> {
        self.session_request_for_txid(
            WitnessServiceOperationV1::Prepare,
            WitnessOperationV1::Prepare,
            WitnessServiceRequestBodyV1::Prepare {
                session: Box::new(self.session.clone()),
                expected_head: None,
                candidate: Box::new(candidate.clone()),
            },
            &candidate.txid,
        )
    }

    fn prepare_request_for_current_candidate(
        &self,
        candidate: &CandidateV1,
        expected_head: &WitnessHeadV1,
    ) -> ProtocolResult<WitnessServiceRequestV1> {
        let mut request = WitnessServiceRequestV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            operation: WitnessServiceOperationV1::Prepare,
            request_nonce: "a".repeat(64),
            admission_digest: self.admission.admission_digest.clone(),
            body: WitnessServiceRequestBodyV1::Prepare {
                session: Box::new(self.session.clone()),
                expected_head: Some(Box::new(expected_head.clone())),
                candidate: Box::new(candidate.clone()),
            },
            request_digest: "0".repeat(64),
            authorization: None,
        };
        rebind_outer_identity(&mut request)?;
        request.authorization = Some(authorization(
            &self.ephemeral,
            &self.session,
            WitnessOperationV1::Prepare,
            &candidate.txid,
            &request.request_digest,
        )?);
        request.validate_public_dispatch_identity()?;
        Ok(request)
    }

    fn candidate_after_head_with_intent(
        &self,
        head: &WitnessHeadV1,
        intent_counter: u64,
    ) -> ProtocolResult<CandidateV1> {
        let mut preimage = candidate(&self.governance, &self.binding)?;
        preimage.predecessor_head = Some(head.clone());
        preimage.predecessor_head_digest = head.head_digest()?;
        preimage.predecessor_data_head_digest = head.data_head_digest()?;
        preimage.publication_mapping_before = head.publication_mapping;
        preimage.publication_mapping_after = PublicationMappingV1 {
            state_canonical: head.publication_mapping.state_staging,
            state_staging: head.publication_mapping.state_canonical,
            checkpoint_canonical: head.publication_mapping.checkpoint_staging,
            checkpoint_staging: head.publication_mapping.checkpoint_canonical,
            journal_primary: head.publication_mapping.journal_primary,
            journal_secondary: head.publication_mapping.journal_secondary,
        };
        preimage.epoch = head.epoch;
        preimage.sequence = head
            .sequence
            .checked_add(1)
            .ok_or(ProtocolError::Overflow {
                counter: "sequence",
            })?;
        preimage.intent_counter = intent_counter;
        build_candidate_without_intent_relation(preimage)
    }

    fn candidate_for_intent(&self, intent_counter: u64) -> ProtocolResult<CandidateV1> {
        let mut preimage = candidate(&self.governance, &self.binding)?;
        preimage.intent_counter = intent_counter;
        preimage.build()
    }

    fn establish_request(&self) -> ProtocolResult<WitnessServiceRequestV1> {
        let challenge = self.current_challenge()?;
        finalized_request(
            WitnessServiceOperationV1::Establish,
            self.admission.admission_digest.clone(),
            WitnessServiceRequestBodyV1::Establish {
                challenge: Box::new(challenge),
                expected_head: None,
            },
            None,
        )
    }

    fn discover_request(&self) -> ProtocolResult<WitnessServiceRequestV1> {
        finalized_request(
            WitnessServiceOperationV1::Discover,
            self.admission.admission_digest.clone(),
            WitnessServiceRequestBodyV1::Discover {
                challenge: Box::new(self.current_challenge()?),
            },
            None,
        )
    }

    fn commit_request(&self) -> ProtocolResult<WitnessServiceRequestV1> {
        self.session_request(
            WitnessServiceOperationV1::Commit,
            WitnessOperationV1::Commit,
            WitnessServiceRequestBodyV1::Commit {
                session: Box::new(self.session.clone()),
                txid: self.candidate.txid.clone(),
            },
        )
    }

    fn abort_request(&self) -> ProtocolResult<WitnessServiceRequestV1> {
        self.session_request(
            WitnessServiceOperationV1::Abort,
            WitnessOperationV1::Abort,
            WitnessServiceRequestBodyV1::Abort {
                session: Box::new(self.session.clone()),
                txid: self.candidate.txid.clone(),
            },
        )
    }

    async fn dispatch_request(
        &self,
        dispatcher: &PublicWitnessDispatcher<RecordingProxy>,
        request: &WitnessServiceRequestV1,
    ) -> ProtocolResult<WitnessServiceResponseV1> {
        let bytes = dispatcher
            .dispatch(
                PublicWitnessServiceConfigV1::subject_for(request.operation),
                &request.canonical_bytes()?,
            )
            .await
            .map_err(dispatch_error)?;
        WitnessServiceResponseV1::decode_for_client_request(&bytes, request)
    }

    async fn dispatch_outer_valid_request(
        &self,
        dispatcher: &PublicWitnessDispatcher<RecordingProxy>,
        request: &WitnessServiceRequestV1,
    ) -> ProtocolResult<WitnessServiceResponseV1> {
        request.validate_public_dispatch_identity()?;
        let bytes = dispatcher
            .dispatch(
                PublicWitnessServiceConfigV1::subject_for(request.operation),
                &canonical_wire_bytes(request)?,
            )
            .await
            .map_err(dispatch_error)?;
        WitnessServiceResponseV1::decode_for_client_request(&bytes, request)
    }

    fn current_challenge(&self) -> ProtocolResult<RecoveryChallengeV1> {
        let state = self
            .proxy
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut request = WitnessSessionFenceRequestV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            stream_id: self.binding.stream_id.clone(),
            authority_pair: self.binding.authority_pair,
            binding_generation: self.binding.generation.clone(),
            binding_digest: self.binding.binding_digest.clone(),
            signer_key_id: self.binding.signer_key_id.clone(),
            witness_key_id: self.binding.witness_key_id.clone(),
            witness_identity: self.binding.witness_identity.clone(),
            requester_nonce: "e".repeat(64),
            signature: self.governance.sign(&[]),
        };
        request.signature = self.governance.sign(&request.signing_bytes()?);
        let current_session_digest = state
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
        let current_head_digest = state
            .envelope
            .current
            .as_ref()
            .map(|current| current.head.head_digest())
            .transpose()?;
        let current_prepared_digest = state
            .envelope
            .prepared
            .as_ref()
            .map(|prepared| {
                digest_domain(
                    WITNESS_PREPARED_STATE_DOMAIN_V1,
                    &canonical_wire_bytes(&prepared.prepared)?,
                )
            })
            .transpose()?;
        let mut fence = WitnessSessionStateFenceV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            request,
            admission_digest: self.admission.admission_digest.clone(),
            bucket_epoch_digest: state.envelope.bucket_epoch_digest.clone(),
            bucket_anchor_digest: "4".repeat(64),
            ready_manifest_digest: self
                .proxy
                .ready_manifest
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .digest()?,
            store_state_digest: state.envelope.store_state_digest()?,
            current_session_generation: state
                .envelope
                .session
                .as_ref()
                .map(|session| session.session_generation),
            current_session_digest,
            current_head_digest,
            current_prepared_digest,
            witness_nonce: "f".repeat(64),
            witness_identity: self.binding.witness_identity.clone(),
            witness_key_id: self.binding.witness_key_id.clone(),
            signature: self.witness.sign(&[]),
        };
        fence.signature = self.witness.sign(&fence.signing_bytes()?);
        let mut challenge = RecoveryChallengeV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            stream_id: self.binding.stream_id.clone(),
            authority_pair: self.binding.authority_pair,
            binding_generation: self.binding.generation.clone(),
            binding_digest: self.binding.binding_digest.clone(),
            signer_key_id: self.binding.signer_key_id.clone(),
            witness_key_id: self.binding.witness_key_id.clone(),
            witness_identity: self.binding.witness_identity.clone(),
            state_fence: fence,
            ephemeral_key_id: self.ephemeral.key_id().to_string(),
            nonce: "7".repeat(64),
            session_commitment: "8".repeat(64),
            signature: self.governance.sign(&[]),
        };
        challenge.signature = self.governance.sign(&challenge.signing_bytes()?);
        challenge.validate()?;
        Ok(challenge)
    }

    fn read_prepared_request(&self) -> ProtocolResult<WitnessServiceRequestV1> {
        self.session_request(
            WitnessServiceOperationV1::ReadPrepared,
            WitnessOperationV1::ReadPrepared,
            WitnessServiceRequestBodyV1::ReadPrepared {
                session: Box::new(self.session.clone()),
                target_txid: self.candidate.txid.clone(),
            },
        )
    }

    fn read_head_request(&self) -> ProtocolResult<WitnessServiceRequestV1> {
        self.session_request(
            WitnessServiceOperationV1::ReadHead,
            WitnessOperationV1::ReadHead,
            WitnessServiceRequestBodyV1::ReadHead {
                session: Box::new(self.session.clone()),
                target_txid: self.candidate.txid.clone(),
            },
        )
    }

    fn fetch_payload_request(&self) -> ProtocolResult<WitnessServiceRequestV1> {
        self.session_request(
            WitnessServiceOperationV1::FetchPayload,
            WitnessOperationV1::FetchPayload,
            WitnessServiceRequestBodyV1::FetchPayload {
                session: Box::new(self.session.clone()),
                txid: self.candidate.txid.clone(),
            },
        )
    }

    fn rotate_current_session(&self, rotations: usize) -> ProtocolResult<()> {
        for index in 0..rotations {
            let challenge = self.current_challenge()?;
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
                session_generation: challenge.expected_session_generation()?,
                session_commitment: challenge.session_commitment.clone(),
            };
            let state = self
                .proxy
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let discovery = WitnessDiscoveryV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                head: state
                    .envelope
                    .current
                    .as_ref()
                    .map(|stored| stored.head.clone()),
                prepared: state
                    .envelope
                    .prepared
                    .as_ref()
                    .map(|stored| stored.prepared.clone()),
                genesis_abort: state.envelope.genesis_abort.clone(),
                recovery_session: session.clone(),
            };
            drop(state);
            let receipt = WitnessSessionRotationReceiptV1::for_discovery(
                digest_domain(
                    b"phase285-public-stale-rotation.v1",
                    &u64::try_from(index)
                        .map_err(|_| ProtocolError::Overflow {
                            counter: "rotation",
                        })?
                        .to_be_bytes(),
                )?,
                &challenge,
                discovery,
            )?;
            let mut state = self
                .proxy
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(prepared) = &mut state.envelope.prepared {
                prepared.prepared.session_generation = session.session_generation;
            }
            state.envelope.session = Some(session);
            state.envelope.last_session_rotation = Some(receipt);
            state.envelope.store_generation = state
                .envelope
                .store_generation
                .checked_add(1)
                .ok_or(ProtocolError::Overflow {
                    counter: "store_generation",
                })?;
            state.envelope.signature = self.witness.sign(&state.envelope.signing_bytes()?);
            state.envelope.validate()?;
            state.revision = state
                .revision
                .checked_add(1)
                .ok_or(ProtocolError::Overflow {
                    counter: "revision",
                })?;
        }
        Ok(())
    }

    fn exhaust_current_session_generation(&self) -> ProtocolResult<()> {
        self.rotate_current_session(1)?;
        let mut state = self
            .proxy
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .envelope
            .session
            .as_mut()
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?
            .session_generation = u64::MAX;
        let receipt = state
            .envelope
            .last_session_rotation
            .as_mut()
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        receipt.session.session_generation = u64::MAX;
        receipt
            .discovery_snapshot
            .as_mut()
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?
            .recovery_session
            .session_generation = u64::MAX;
        state.envelope.signature = self.witness.sign(&state.envelope.signing_bytes()?);
        state.envelope.validate()
    }

    fn session_request(
        &self,
        operation: WitnessServiceOperationV1,
        authorization_operation: WitnessOperationV1,
        body: WitnessServiceRequestBodyV1,
    ) -> ProtocolResult<WitnessServiceRequestV1> {
        self.session_request_for_txid(
            operation,
            authorization_operation,
            body,
            &self.candidate.txid,
        )
    }

    fn session_request_for_txid(
        &self,
        operation: WitnessServiceOperationV1,
        authorization_operation: WitnessOperationV1,
        body: WitnessServiceRequestBodyV1,
        target_txid: &str,
    ) -> ProtocolResult<WitnessServiceRequestV1> {
        let mut request = finalized_request(
            operation,
            self.admission.admission_digest.clone(),
            body,
            None,
        )?;
        request.authorization = Some(authorization(
            &self.ephemeral,
            &self.session,
            authorization_operation,
            target_txid,
            &request.request_digest,
        )?);
        request.validate()?;
        Ok(request)
    }
}

fn finalized_request(
    operation: WitnessServiceOperationV1,
    admission_digest: String,
    body: WitnessServiceRequestBodyV1,
    authorization: Option<WitnessSessionAuthorizationV1>,
) -> ProtocolResult<WitnessServiceRequestV1> {
    let mut request = WitnessServiceRequestV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        operation,
        request_nonce: "a".repeat(64),
        admission_digest,
        body,
        request_digest: "0".repeat(64),
        authorization,
    };
    request.request_digest = request.computed_digest()?;
    if request.authorization.is_none()
        && !matches!(
            request.operation,
            WitnessServiceOperationV1::Fence
                | WitnessServiceOperationV1::Establish
                | WitnessServiceOperationV1::Discover
        )
    {
        return Ok(request);
    }
    request.validate()?;
    Ok(request)
}

#[derive(Serialize)]
struct OuterRequestPreimage<'a> {
    schema_version: u32,
    operation: WitnessServiceOperationV1,
    request_nonce: &'a str,
    admission_digest: &'a str,
    body: &'a WitnessServiceRequestBodyV1,
}

fn rebind_outer_request(
    request: &mut WitnessServiceRequestV1,
    ephemeral: &Ed25519Signer,
    session: &WitnessSessionV1,
    authorization_operation: WitnessOperationV1,
    target_txid: &str,
) -> ProtocolResult<()> {
    request.authorization = None;
    rebind_outer_identity(request)?;
    request.authorization = Some(authorization(
        ephemeral,
        session,
        authorization_operation,
        target_txid,
        &request.request_digest,
    )?);
    request.validate_public_dispatch_identity()
}

fn rebind_outer_identity(request: &mut WitnessServiceRequestV1) -> ProtocolResult<()> {
    request.request_digest = digest_domain(
        WITNESS_SERVICE_REQUEST_DOMAIN_V1,
        &canonical_wire_bytes(&OuterRequestPreimage {
            schema_version: request.schema_version,
            operation: request.operation,
            request_nonce: &request.request_nonce,
            admission_digest: &request.admission_digest,
            body: &request.body,
        })?,
    )?;
    request.validate_public_dispatch_identity()
}

fn admission(binding: &PublicationBindingV1) -> ProtocolResult<WitnessAdmissionRecordV1> {
    let mut value = WitnessAdmissionRecordV1 {
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
    value.admission_digest = value.computed_digest()?;
    value.validate()?;
    Ok(value)
}

fn binding(
    governance: &Ed25519Signer,
    witness: &Ed25519Signer,
) -> ProtocolResult<PublicationBindingV1> {
    let roles = PublicationRoleIdentitiesV1 {
        state_canonical: artifact(1),
        state_staging: artifact(2),
        checkpoint_canonical: artifact(3),
        checkpoint_staging: artifact(4),
        journal_primary: artifact(5),
        journal_secondary: artifact(6),
    };
    let mut value = PublicationBindingV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: "tom-primary".to_string(),
        generation: "9".repeat(64),
        parent_directory: artifact(7),
        pool_directory: artifact(8),
        pool_lock: artifact(9),
        binding_file: artifact(10),
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
            .map(artifact)
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

const fn artifact(inode: u64) -> ArtifactIdentityV1 {
    ArtifactIdentityV1 { device: 2, inode }
}

fn candidate(
    governance: &Ed25519Signer,
    binding: &PublicationBindingV1,
) -> ProtocolResult<CandidatePreimageV1> {
    let before = PublicationMappingV1 {
        state_canonical: binding.publication_roles.state_canonical,
        state_staging: binding.publication_roles.state_staging,
        checkpoint_canonical: binding.publication_roles.checkpoint_canonical,
        checkpoint_staging: binding.publication_roles.checkpoint_staging,
        journal_primary: binding.publication_roles.journal_primary,
        journal_secondary: binding.publication_roles.journal_secondary,
    };
    let state_payload = br#"{"state":1}"#.to_vec();
    let checkpoint_payload = br#"{"checkpoint":1}"#.to_vec();
    let state_digest = sha256_hex(&state_payload);
    let checkpoint_digest = sha256_hex(&checkpoint_payload);
    let genesis = GenesisPredecessorV1::for_binding(binding);
    let value = CandidatePreimageV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: binding.stream_id.clone(),
        predecessor_head: None,
        predecessor_head_digest: genesis.digest()?,
        predecessor_data_head_digest: genesis.data_head_digest()?,
        state_payload: state_payload.clone(),
        state_byte_len: state_payload.len() as u64,
        state_digest: state_digest.clone(),
        state_attestation: sign_payload(
            governance,
            STATE_PAYLOAD_DOMAIN_V1,
            binding,
            state_payload,
            state_digest,
        )?,
        checkpoint_payload: checkpoint_payload.clone(),
        checkpoint_byte_len: checkpoint_payload.len() as u64,
        checkpoint_digest: checkpoint_digest.clone(),
        checkpoint_attestation: sign_payload(
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
    };
    value.validate()?;
    Ok(value)
}

fn build_candidate_without_intent_relation(
    preimage: CandidatePreimageV1,
) -> ProtocolResult<CandidateV1> {
    let candidate_digest = digest_domain(CANDIDATE_DOMAIN_V1, &canonical_wire_bytes(&preimage)?)?;
    let txid = TxidPreimageV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: preimage.stream_id.clone(),
        predecessor_head_digest: preimage.predecessor_head_digest.clone(),
        candidate_digest: candidate_digest.clone(),
        binding_generation: preimage.publication_binding.generation.clone(),
        binding_digest: preimage.publication_binding.binding_digest.clone(),
        authority_pair: preimage.publication_binding.authority_pair,
        epoch: preimage.epoch,
        sequence: preimage.sequence,
        intent_counter: preimage.intent_counter,
    }
    .txid()?;
    Ok(CandidateV1 {
        preimage,
        candidate_digest,
        txid,
    })
}

fn sign_payload(
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

fn authorization(
    ephemeral: &Ed25519Signer,
    session: &WitnessSessionV1,
    operation: WitnessOperationV1,
    txid: &str,
    request_digest: &str,
) -> ProtocolResult<WitnessSessionAuthorizationV1> {
    let preimage = AuthorizationPreimage {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        operation,
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
        operation,
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

fn dispatch_error(error: PublicWitnessDispatchErrorV1) -> ProtocolError {
    ProtocolError::CanonicalEncoding(error.to_string())
}

fn join_error(error: tokio::task::JoinError) -> ProtocolError {
    ProtocolError::CanonicalEncoding(error.to_string())
}

fn write_dispatcher_mapping_ledger() -> ProtocolResult<()> {
    let required = std::env::var_os("PHASE285_DISPATCHER_MAPPING_LEDGER_REQUIRED").is_some();
    let Some(path) = std::env::var_os("PHASE285_DISPATCHER_MAPPING_LEDGER") else {
        if required {
            return Err(ProtocolError::InvalidField {
                field: "dispatcher_mapping_ledger".to_string(),
                reason: "required ledger path is absent".to_string(),
            });
        }
        return Ok(());
    };
    use sha2::{Digest, Sha256};
    use std::fs::OpenOptions;
    use std::io::Write;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    for mapping in dispatcher_mapping() {
        let canonical = serde_json::to_vec(&serde_json::json!({
            "case": "dispatcher-mapping",
            "inner_id": mapping.method,
            "status": "passed",
        }))
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
        let mut preimage = b"swarm.phase285.witness-inner-ledger-row.v1".to_vec();
        preimage.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
        preimage.extend_from_slice(&canonical);
        writeln!(
            file,
            "dispatcher-mapping\t{}\tpassed\t{:x}",
            mapping.method,
            Sha256::digest(preimage)
        )
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    }
    file.sync_all()
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))
}

const CAPABILITY_MATRIX: [&str; 20] = [
    "runtime_private_subject",
    "runtime_raw_kv",
    "runtime_js_api",
    "witness_raw_kv",
    "witness_js_api",
    "init_serving_subject",
    "runtime_credential_swap",
    "witness_credential_swap",
    "store_credential_swap",
    "init_credential_swap",
    "account_swap",
    "mount_swap",
    "reply_subject_injection",
    "wildcard_import",
    "tls_ca_swap",
    "tls_server_name_swap",
    "store_queue_exhaustion",
    "public_store_bypass",
    "private_public_signing",
    "hostile_cleanup_preservation",
];

fn write_capability_row(
    id: &str,
    credential_role: &str,
    account: &str,
    subject: &str,
    expected_failure: &str,
    store_calls_before: usize,
    store_calls_after: usize,
) -> ProtocolResult<()> {
    let required = std::env::var_os("PHASE285_CAPABILITY_MATRIX_LEDGER_REQUIRED").is_some();
    let Some(path) = std::env::var_os("PHASE285_CAPABILITY_MATRIX_LEDGER") else {
        if required {
            return Err(ProtocolError::InvalidField {
                field: "capability_matrix_ledger".to_string(),
                reason: "required ledger path is absent".to_string(),
            });
        }
        return Ok(());
    };
    use sha2::{Digest, Sha256};
    let invocation_token =
        std::env::var("PHASE285_CAPABILITY_MATRIX_INVOCATION_TOKEN").map_err(|_| {
            ProtocolError::InvalidField {
                field: "capability_matrix_invocation_token".to_string(),
                reason: "required invocation token is absent".to_string(),
            }
        })?;
    if invocation_token.is_empty() || invocation_token.len() > 512 {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    use std::fs::OpenOptions;
    use std::io::Write;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    if !CAPABILITY_MATRIX.contains(&id) {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    let canonical = serde_json::to_vec(&serde_json::json!({
        "account": account,
        "case": "capability-matrix",
        "credential_role": credential_role,
        "expected_failure": expected_failure,
        "inner_id": id,
        "invocation_token": invocation_token,
        "status": "passed",
        "store_calls_after": store_calls_after,
        "store_calls_before": store_calls_before,
        "subject": subject,
    }))
    .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    let mut preimage = b"swarm.phase285.capability-evidence-row.v1".to_vec();
    preimage.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
    preimage.extend_from_slice(&canonical);
    writeln!(
        file,
        "capability-matrix\t{id}\tpassed\t{invocation_token}\t{credential_role}\t{account}\t{subject}\t{expected_failure}\t{store_calls_before}\t{store_calls_after}\t{:x}",
        Sha256::digest(preimage)
    )
    .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    file.sync_all()
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))
}

type ReadyFixtureEntries = (
    WitnessStoreReadyResultV1,
    BTreeMap<String, (u64, WitnessStoreEnvelopeV1)>,
);

#[derive(Clone, Copy)]
enum ReadyBindingMutation {
    None,
    Stream,
    Epoch,
    Anchor,
    AdmissionSet,
    SelectedLimits,
}

type StoreConfigMutation = (&'static str, fn(&mut StoreProxyServiceConfigV1));

fn store_ready_fixture_entries(fixture: &Fixture) -> ProtocolResult<ReadyFixtureEntries> {
    store_ready_fixture_entries_with(fixture, ReadyBindingMutation::None)
}

fn store_ready_fixture_entries_with(
    fixture: &Fixture,
    mutation: ReadyBindingMutation,
) -> ProtocolResult<ReadyFixtureEntries> {
    let max_value_bytes = 1_000_000_u64;
    let max_manifest_bytes = 1_000_000_u64;
    let mut admission_set = fixture.admission_set.clone();
    match mutation {
        ReadyBindingMutation::AdmissionSet => {
            admission_set.entries[0].max_request_bytes -= 1;
        }
        ReadyBindingMutation::SelectedLimits => {
            admission_set.entries[0].max_response_bytes -= 1;
        }
        _ => {}
    }
    if matches!(
        mutation,
        ReadyBindingMutation::AdmissionSet | ReadyBindingMutation::SelectedLimits
    ) {
        admission_set.admission_set_digest = admission_set.computed_digest()?;
        admission_set.validate()?;
    }
    let maximum_admitted_streams = admission_set.entries.len() as u64;
    let required_bucket_bytes = 2 * (max_manifest_bytes + 65_536)
        + maximum_admitted_streams * 2 * (max_value_bytes + 65_536);
    let mut configuration = WitnessBucketConfigurationV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        nats_server_version: "2.11.17".to_string(),
        nats_server_image_index_digest:
            "sha256:e4bf19f15fd3218814a4e3c9e0064e1334bd8aa20d5984b9f1a0afd084f8cc00".to_string(),
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
    if matches!(mutation, ReadyBindingMutation::Stream) {
        configuration.stream_name = "KV_phase285_service_alternate".to_string();
        configuration.subjects = vec!["$KV.phase285_service_alternate.>".to_string()];
    }
    configuration.validate()?;
    let configuration_digest = configuration.digest()?;
    let mut epoch = WitnessBucketEpochV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        bucket_generation: "a".repeat(64),
        nats_account: "witness-store".to_string(),
        stream_name: configuration.stream_name.clone(),
        bucket_configuration_digest: configuration_digest.clone(),
        admission_set_digest: admission_set.admission_set_digest.clone(),
        witness_identity: fixture.witness_identity().to_string(),
        witness_key_id: fixture.witness.key_id().to_string(),
    };
    if matches!(mutation, ReadyBindingMutation::Epoch) {
        epoch.bucket_generation = "b".repeat(64);
    }
    let epoch_digest = epoch.digest()?;
    let primary = fixture
        .proxy
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut source_entries = BTreeMap::from([(
        primary.envelope.stream_id.clone(),
        (primary.revision, primary.envelope.clone()),
    )]);
    drop(primary);
    if let Some(secondary) = fixture
        .proxy
        .secondary_state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
    {
        source_entries.insert(
            secondary.envelope.stream_id.clone(),
            (secondary.revision, secondary.envelope.clone()),
        );
    }
    let mut stream_keys = Vec::with_capacity(admission_set.entries.len());
    let mut initialized_streams = BTreeMap::new();
    let mut entries = BTreeMap::new();
    for admission in &admission_set.entries {
        let (revision, mut envelope) = source_entries
            .remove(&admission.stream_id)
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        envelope.admission_digest = admission.admission_digest.clone();
        envelope.bucket_epoch_digest = epoch_digest.clone();
        envelope.stream_initialization_digest = WitnessStreamInitializationV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            bucket_epoch_digest: epoch_digest.clone(),
            admission_digest: admission.admission_digest.clone(),
            stream_id: admission.stream_id.clone(),
            witness_identity: admission.witness_identity.clone(),
            witness_key_id: admission.witness_key_id.clone(),
        }
        .digest()?;
        envelope.signature = fixture.witness.sign(&envelope.signing_bytes()?);
        envelope.validate()?;
        let key = witness_stream_key(&admission.stream_id)?;
        stream_keys.push(key.clone());
        initialized_streams.insert(
            key,
            WitnessStreamInitializationRecordV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                stream_initialization_digest: envelope.stream_initialization_digest.clone(),
                empty_envelope_digest: envelope.signed_envelope_digest()?,
            },
        );
        entries.insert(admission.stream_id.clone(), (revision, envelope));
    }
    stream_keys.sort();
    let mut manifest = WitnessBucketManifestV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        bucket_epoch_digest: epoch_digest,
        bucket_configuration_digest: configuration_digest,
        admission_set_digest: admission_set.admission_set_digest.clone(),
        stream_keys,
        initialized_streams,
        phase: WitnessBucketManifestPhaseV1::Ready,
        witness_identity: fixture.witness_identity().to_string(),
        witness_key_id: fixture.witness.key_id().to_string(),
        signature: fixture.witness.sign(&[]),
    };
    manifest.signature = fixture.witness.sign(&manifest.signing_bytes()?);
    let mut anchor = WitnessBucketAnchorV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        epoch: epoch.clone(),
        nats_stream_created_at: "2026-08-25T00:00:00.000000000Z".to_string(),
        raw_stream_configuration_digest: sha256_hex(b"phase285-service-raw-configuration"),
        ready_manifest_digest: manifest.digest()?,
        witness_key_id: fixture.witness.key_id().to_string(),
        signature: fixture.witness.sign(&[]),
    };
    if matches!(mutation, ReadyBindingMutation::Anchor) {
        anchor.raw_stream_configuration_digest =
            sha256_hex(b"phase285-service-alternate-raw-configuration");
    }
    anchor.signature = fixture.witness.sign(&anchor.signing_bytes()?);
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
            maximum_admitted_streams,
            configured_replica_count: 1,
        },
    )
    .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    Ok((ready, entries))
}

fn store_service_config(
    fixture: &Fixture,
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
        pinned_witness_public_key_hex: fixture.witness.public_key_hex().to_string(),
        witness_key_id: fixture.witness.key_id().to_string(),
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

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HarnessRoleCredentialV1 {
    schema_version: u32,
    role: String,
    username: String,
    password: String,
    invocation_token: String,
}

#[derive(Serialize)]
struct ConstructorDeadlineObservationV1 {
    input_millis: u64,
    result: &'static str,
}

#[derive(Serialize)]
struct ConstructorDeadlineReceiptV1<'a> {
    schema_version: u8,
    tree: &'a str,
    invocation_token: &'a str,
    case: &'a str,
    inner_id: &'static str,
    status: &'static str,
    live_nats_grants_proved: bool,
    launcher_sha256: &'a str,
    manifest_sha256: &'a str,
    observations: &'a [ConstructorDeadlineObservationV1; 5],
    observations_sha256: String,
    store_calls: u64,
}

fn write_constructor_deadline_receipt(
    observations: &[ConstructorDeadlineObservationV1; 5],
) -> ProtocolResult<()> {
    let Some(path) = std::env::var_os("PHASE285_DEADLINE_CONSTRUCTOR_RECEIPT") else {
        return Ok(());
    };
    let tree = std::env::var("PHASE285_DEADLINE_TREE")
        .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
    let token = std::env::var("PHASE285_DEADLINE_INVOCATION_TOKEN")
        .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
    let case = std::env::var("PHASE285_DEADLINE_CASE")
        .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
    let launcher_sha256 = std::env::var("PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256")
        .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
    let manifest_sha256 = std::env::var("PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256")
        .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
    let observations_sha256 = sha256_hex(&canonical_wire_bytes(observations)?);
    let receipt = ConstructorDeadlineReceiptV1 {
        schema_version: 1,
        tree: &tree,
        invocation_token: &token,
        case: &case,
        inner_id: "deadline_budget_constructor_exact",
        status: "passed",
        live_nats_grants_proved: false,
        launcher_sha256: &launcher_sha256,
        manifest_sha256: &manifest_sha256,
        observations,
        observations_sha256,
        store_calls: 0,
    };
    let bytes = canonical_wire_bytes(&receipt)?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
    use std::io::Write as _;
    output
        .write_all(&bytes)
        .and_then(|()| output.write_all(b"\n"))
        .and_then(|()| output.sync_all())
        .map_err(|_| ProtocolError::WitnessOutcomeMismatch)
}

#[tokio::test]
async fn full_service_path_constructor_deadline_is_exact_and_receipt_bound() -> ProtocolResult<()> {
    let client = connect_harness_role("SWARM_NATS_WITNESS_CREDENTIAL_PATH", "witness").await?;
    let observations = [0, 2_999, 3_000, 3_001, u64::MAX].map(|input_millis| {
        let result = NatsPublicWitnessStoreProxyClient::new(
            client.clone(),
            MAX_PROTOCOL_RECORD_BYTES,
            MAX_PROTOCOL_RECORD_BYTES,
            input_millis,
        );
        ConstructorDeadlineObservationV1 {
            input_millis,
            result: if result.is_ok() {
                "accepted"
            } else {
                "refused"
            },
        }
    });
    assert_eq!(
        observations
            .each_ref()
            .map(|observation| (observation.input_millis, observation.result)),
        [
            (0, "refused"),
            (2_999, "refused"),
            (3_000, "accepted"),
            (3_001, "refused"),
            (u64::MAX, "refused"),
        ],
        "deadline_r24_constructor_results"
    );
    write_constructor_deadline_receipt(&observations)
}

fn mutated_harness_credential<F>(
    source_variable: &str,
    label: &str,
    mutate: F,
) -> ProtocolResult<std::path::PathBuf>
where
    F: FnOnce(&mut HarnessRoleCredentialV1),
{
    use std::fs::OpenOptions;
    use std::io::Write;
    let source = std::env::var(source_variable).map_err(|_| ProtocolError::InvalidField {
        field: source_variable.to_string(),
        reason: "wrapped TLS credential is required".to_string(),
    })?;
    let raw = std::fs::read(source)
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    let mut credential: HarnessRoleCredentialV1 = serde_json::from_slice(&raw)
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    mutate(&mut credential);
    let root =
        std::path::PathBuf::from(std::env::var("SWARM_NATS_HARNESS_SCRATCH").map_err(|_| {
            ProtocolError::InvalidField {
                field: "SWARM_NATS_HARNESS_SCRATCH".to_string(),
                reason: "wrapped scratch is required".to_string(),
            }
        })?);
    let path = root.join(format!("credential-mutant-{label}.json"));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    file.write_all(
        &serde_json::to_vec(&credential)
            .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?,
    )
    .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    file.sync_all()
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    Ok(path)
}

async fn connect_harness_role(
    path_variable: &str,
    expected_role: &str,
) -> ProtocolResult<async_nats::Client> {
    let path = std::env::var(path_variable).map_err(|_| ProtocolError::InvalidField {
        field: path_variable.to_string(),
        reason: "wrapped TLS credential is required".to_string(),
    })?;
    let raw =
        std::fs::read(path).map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    let credential: HarnessRoleCredentialV1 = serde_json::from_slice(&raw)
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    let token = std::env::var("SWARM_NATS_TLS_CREDENTIAL_TOKEN").map_err(|_| {
        ProtocolError::InvalidField {
            field: "SWARM_NATS_TLS_CREDENTIAL_TOKEN".to_string(),
            reason: "wrapped TLS credential token is required".to_string(),
        }
    })?;
    if credential.schema_version != PROTOCOL_SCHEMA_VERSION
        || credential.role != expected_role
        || credential.invocation_token != token
    {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    let url =
        std::env::var("SWARM_NATS_STORE_TLS_URL").map_err(|_| ProtocolError::InvalidField {
            field: "SWARM_NATS_STORE_TLS_URL".to_string(),
            reason: "wrapped TLS endpoint is required".to_string(),
        })?;
    let ca = std::env::var("SWARM_NATS_TLS_CA_PATH").map_err(|_| ProtocolError::InvalidField {
        field: "SWARM_NATS_TLS_CA_PATH".to_string(),
        reason: "wrapped TLS CA is required".to_string(),
    })?;
    async_nats::ConnectOptions::with_user_and_password(credential.username, credential.password)
        .require_tls(true)
        .add_root_certificates(ca.into())
        .connection_timeout(std::time::Duration::from_secs(2))
        .request_timeout(Some(std::time::Duration::from_secs(2)))
        .connect(url)
        .await
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))
}

async fn assert_live_subject_refused(
    client: &async_nats::Client,
    subject: &str,
    payload: &[u8],
) -> ProtocolResult<()> {
    match tokio::time::timeout(
        std::time::Duration::from_millis(1_500),
        client.request(subject.to_string(), payload.to_vec().into()),
    )
    .await
    {
        Err(_) | Ok(Err(_)) => Ok(()),
        Ok(Ok(message)) => {
            let value: serde_json::Value = serde_json::from_slice(&message.payload)
                .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
            if value.get("error").is_none() {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
            Ok(())
        }
    }
}

async fn initialize_harness_store_stream() -> ProtocolResult<()> {
    let client = connect_harness_role("SWARM_NATS_INIT_CREDENTIAL_PATH", "init").await?;
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
            .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string())),
    }
}

fn signed_store_request(
    fixture: &Fixture,
    ready: &WitnessStoreReadyResultV1,
    operation: WitnessStoreProxyOperationV1,
    body: WitnessStoreProxyRequestBodyV1,
) -> ProtocolResult<WitnessStoreProxyRequestV1> {
    let admission = ready
        .entry(&fixture.admission.stream_id)
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    signed_store_request_for_admission(fixture, ready, admission, operation, body)
}

fn signed_store_request_for_admission(
    fixture: &Fixture,
    ready: &WitnessStoreReadyResultV1,
    admission: &WitnessAdmissionEntryV1,
    operation: WitnessStoreProxyOperationV1,
    body: WitnessStoreProxyRequestBodyV1,
) -> ProtocolResult<WitnessStoreProxyRequestV1> {
    let mut request = WitnessStoreProxyRequestV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        operation,
        request_nonce: "a".repeat(64),
        admission_digest: admission.admission_digest.clone(),
        bucket_epoch_digest: ready.bucket_epoch.digest()?,
        bucket_anchor_digest: ready.bucket_anchor.digest()?,
        body,
        request_digest: String::new(),
        witness_key_id: fixture.witness.key_id().to_string(),
        signature: fixture.witness.sign(&[]),
    };
    request.request_digest = request.computed_digest()?;
    request.signature = fixture.witness.sign(&request.signing_bytes()?);
    request.validate_structure()?;
    request.validate_semantics()?;
    request.validate_signature()?;
    Ok(request)
}

struct CountingAtomicStore {
    inner: InMemoryWitnessStore,
    calls: Arc<AtomicUsize>,
}

struct BlockingReadAtomicStore {
    inner: InMemoryWitnessStore,
    calls: Arc<AtomicUsize>,
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

#[async_trait]
impl WitnessAtomicStore for BlockingReadAtomicStore {
    async fn inspect_ready(&self) -> Result<WitnessStoreReadyResultV1, WitnessStoreErrorV1> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.inspect_ready().await
    }

    async fn read_entry(
        &self,
        stream_id: &str,
    ) -> Result<WitnessStoreReadResultV1, WitnessStoreErrorV1> {
        let ordinal = self.calls.fetch_add(1, Ordering::SeqCst);
        if ordinal == 0 {
            self.entered.notify_one();
            self.release.notified().await;
        }
        self.inner.read_entry(stream_id).await
    }

    async fn compare_and_swap(
        &self,
        stream_id: &str,
        expected_revision: u64,
        expected_store_state_digest: &str,
        proposed_envelope: &WitnessStoreEnvelopeV1,
    ) -> Result<WitnessStoreCasResultV1, WitnessStoreErrorV1> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .compare_and_swap(
                stream_id,
                expected_revision,
                expected_store_state_digest,
                proposed_envelope,
            )
            .await
    }
}

#[async_trait]
impl WitnessAtomicStore for CountingAtomicStore {
    async fn inspect_ready(&self) -> Result<WitnessStoreReadyResultV1, WitnessStoreErrorV1> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.inspect_ready().await
    }

    async fn read_entry(
        &self,
        stream_id: &str,
    ) -> Result<WitnessStoreReadResultV1, WitnessStoreErrorV1> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.read_entry(stream_id).await
    }

    async fn compare_and_swap(
        &self,
        stream_id: &str,
        expected_revision: u64,
        expected_store_state_digest: &str,
        proposed_envelope: &WitnessStoreEnvelopeV1,
    ) -> Result<WitnessStoreCasResultV1, WitnessStoreErrorV1> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .compare_and_swap(
                stream_id,
                expected_revision,
                expected_store_state_digest,
                proposed_envelope,
            )
            .await
    }
}

fn counting_store(
    ready: WitnessStoreReadyResultV1,
    entries: BTreeMap<String, (u64, WitnessStoreEnvelopeV1)>,
) -> ProtocolResult<(CountingAtomicStore, Arc<AtomicUsize>)> {
    let calls = Arc::new(AtomicUsize::new(0));
    let inner = InMemoryWitnessStore::new(ready, entries, 2_000_000)
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    Ok((
        CountingAtomicStore {
            inner,
            calls: calls.clone(),
        },
        calls,
    ))
}

async fn secondary_response_bytes_at_limit(
    limit: Option<u64>,
) -> ProtocolResult<(Result<Vec<u8>, StoreProxyServiceErrorV1>, usize, usize)> {
    let mut fixture = Fixture::new(CasMode::Apply)?;
    fixture.enable_second_stream_with(|entry| {
        if let Some(limit) = limit {
            entry.max_response_bytes = limit;
        }
    })?;
    let secondary_stream = fixture
        .admission_set
        .entries
        .iter()
        .find(|entry| entry.stream_id != fixture.admission.stream_id)
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .stream_id
        .clone();
    let (ready, entries) = store_ready_fixture_entries(&fixture)?;
    let admission = ready
        .admission_set
        .entries
        .iter()
        .find(|entry| entry.stream_id == secondary_stream)
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    let request = signed_store_request_for_admission(
        &fixture,
        &ready,
        admission,
        WitnessStoreProxyOperationV1::ReadEntry,
        WitnessStoreProxyRequestBodyV1::ReadEntry {
            stream_id: admission.stream_id.clone(),
        },
    )?;
    let raw = canonical_wire_bytes(&request)?;
    let (store, calls) = counting_store(ready.clone(), entries)?;
    let mut config = store_service_config(&fixture, &ready)?;
    config.max_response_bytes = MAX_PROTOCOL_RECORD_BYTES;
    let service = StoreProxyService::new(config, ready, store)
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    let result = service
        .handle_subject_bytes(store_proxy_subjects()[1], &raw)
        .await;
    Ok((result, calls.load(Ordering::SeqCst), raw.len()))
}

async fn selected_overload_response_at_limit(
    response_limit: u64,
) -> ProtocolResult<(Option<Vec<u8>>, usize, usize, Vec<u8>)> {
    let mut fixture = Fixture::new(CasMode::Apply)?;
    fixture.enable_second_stream_with(|entry| entry.max_response_bytes = response_limit)?;
    let secondary = fixture
        .admission_set
        .entries
        .iter()
        .find(|entry| entry.stream_id != fixture.admission.stream_id)
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .clone();
    let (ready, entries) = store_ready_fixture_entries(&fixture)?;
    let request = signed_store_request_for_admission(
        &fixture,
        &ready,
        &secondary,
        WitnessStoreProxyOperationV1::ReadEntry,
        WitnessStoreProxyRequestBodyV1::ReadEntry {
            stream_id: secondary.stream_id.clone(),
        },
    )?;
    let expected_overload = WitnessStoreProxyResponseV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        operation: request.operation,
        request_digest: request.request_digest.clone(),
        body: WitnessStoreProxyResponseBodyV1::Refused {
            failure_code: WitnessStoreProxyFailureCodeV1::Unavailable,
            observed_revision: None,
            observed_value_digest: None,
        },
    }
    .canonical_bytes()?;
    let raw = canonical_wire_bytes(&request)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let inner = InMemoryWitnessStore::new(ready.clone(), entries, 2_000_000)
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    let store = BlockingReadAtomicStore {
        inner,
        calls: calls.clone(),
        entered: entered.clone(),
        release: release.clone(),
    };
    let mut config = store_service_config(&fixture, &ready)?;
    config.ingress_queue_capacity = 1;
    config.max_in_flight = 1;
    let service = StoreProxyService::new(config.clone(), ready.clone(), store)
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    initialize_harness_store_stream().await?;
    let connection = StoreRoleConnectionV1::connect(&config, &ready)
        .await
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    let runner = StoreProxyServiceRunner::start(connection, service)
        .await
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    let client = connect_harness_role("SWARM_NATS_WITNESS_CREDENTIAL_PATH", "witness").await?;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let first_client = client.clone();
    let first_raw = raw.clone();
    let first = tokio::spawn(async move {
        first_client
            .request(store_proxy_subjects()[1], first_raw.into())
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), entered.notified())
        .await
        .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
    let second_client = client.clone();
    let second_raw = raw.clone();
    let second = tokio::spawn(async move {
        second_client
            .request(store_proxy_subjects()[1], second_raw.into())
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(75)).await;
    let before = calls.load(Ordering::SeqCst);
    let overloaded = tokio::time::timeout(
        std::time::Duration::from_millis(400),
        client.request(store_proxy_subjects()[1], raw.into()),
    )
    .await
    .ok()
    .and_then(Result::ok)
    .map(|message| message.payload.to_vec());
    let after = calls.load(Ordering::SeqCst);
    release.notify_waiters();
    let _ = first.await.map_err(join_error)?;
    let _ = second.await.map_err(join_error)?;
    drop(runner);
    Ok((overloaded, before, after, expected_overload))
}

async fn assert_connection_service_ready_mismatch(
    label: &str,
    connection_config: &StoreProxyServiceConfigV1,
    connection_ready: &WitnessStoreReadyResultV1,
    service_config: StoreProxyServiceConfigV1,
    service_ready: WitnessStoreReadyResultV1,
    service_entries: BTreeMap<String, (u64, WitnessStoreEnvelopeV1)>,
) -> ProtocolResult<()> {
    service_config.validate_for_ready(&service_ready)?;
    let (store, calls) = counting_store(service_ready.clone(), service_entries)?;
    let service = StoreProxyService::new(service_config, service_ready, store)
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    let connection = StoreRoleConnectionV1::connect(connection_config, connection_ready)
        .await
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    assert!(
        matches!(
            StoreProxyServiceRunner::start(connection, service).await,
            Err(swarm_governance_witness::StoreProxyRunnerErrorV1::Configuration)
        ),
        "connection/service Ready binding mismatch survived: {label}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "binding mismatch touched the raw store: {label}"
    );
    Ok(())
}

#[tokio::test]
async fn full_service_path_rejects_runtime_private_subject_and_store_raw_api() -> ProtocolResult<()>
{
    let fixture = Fixture::new(CasMode::Apply)?;
    let (ready, entries) = store_ready_fixture_entries(&fixture)?;
    let (store, calls) = counting_store(ready.clone(), entries)?;
    let service = StoreProxyService::new(
        store_service_config(&fixture, &ready)?,
        ready.clone(),
        store,
    )
    .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    let request = signed_store_request(
        &fixture,
        &ready,
        WitnessStoreProxyOperationV1::ReadEntry,
        WitnessStoreProxyRequestBodyV1::ReadEntry {
            stream_id: fixture.admission.stream_id.clone(),
        },
    )?;
    let raw = canonical_wire_bytes(&request)?;
    initialize_harness_store_stream().await?;
    let connection =
        StoreRoleConnectionV1::connect(&store_service_config(&fixture, &ready)?, &ready)
            .await
            .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    let _runner = StoreProxyServiceRunner::start(connection, service)
        .await
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    let runtime = connect_harness_role("SWARM_NATS_RUNTIME_CREDENTIAL_PATH", "runtime").await?;
    let witness = connect_harness_role("SWARM_NATS_WITNESS_CREDENTIAL_PATH", "witness").await?;
    let init = connect_harness_role("SWARM_NATS_INIT_CREDENTIAL_PATH", "init").await?;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let stream_key = witness_stream_key(&fixture.admission.stream_id)?;
    let raw_subject = format!("$KV.phase285_service.{stream_key}");
    for (client, role, account, subject, capability, failure) in [
        (
            &runtime,
            "runtime",
            "PHASE285_RUNTIME",
            store_proxy_subjects()[1].to_string(),
            "runtime_private_subject",
            "no_private_import",
        ),
        (
            &runtime,
            "runtime",
            "PHASE285_RUNTIME",
            raw_subject.clone(),
            "runtime_raw_kv",
            "raw_subject_refused",
        ),
        (
            &runtime,
            "runtime",
            "PHASE285_RUNTIME",
            "$JS.API.STREAM.INFO.KV_phase285_service".to_string(),
            "runtime_js_api",
            "foreign_stream_invisible",
        ),
        (
            &witness,
            "witness",
            "PHASE285_WITNESS",
            raw_subject,
            "witness_raw_kv",
            "raw_subject_refused",
        ),
        (
            &witness,
            "witness",
            "PHASE285_WITNESS",
            "$JS.API.STREAM.INFO.KV_phase285_service".to_string(),
            "witness_js_api",
            "raw_api_refused",
        ),
        (
            &init,
            "init",
            "PHASE285_WITNESS_STORE",
            store_proxy_subjects()[1].to_string(),
            "init_serving_subject",
            "serving_subject_refused",
        ),
    ] {
        let before = calls.load(Ordering::SeqCst);
        let payload = if capability == "runtime_js_api" {
            b"{}".as_slice()
        } else {
            raw.as_slice()
        };
        assert_live_subject_refused(client, &subject, payload).await?;
        let after = calls.load(Ordering::SeqCst);
        assert_eq!(after, before);
        write_capability_row(capability, role, account, &subject, failure, before, after)?;
    }
    Ok(())
}

#[tokio::test]
async fn full_service_path_rejects_credential_account_and_mount_swaps() -> ProtocolResult<()> {
    let fixture = Fixture::new(CasMode::Apply)?;
    let (ready, entries) = store_ready_fixture_entries(&fixture)?;
    let config = store_service_config(&fixture, &ready)?;
    config.validate_for_ready(&ready)?;
    initialize_harness_store_stream().await?;
    StoreRoleConnectionV1::connect(&config, &ready)
        .await
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;

    let config_mutations: [StoreConfigMutation; 10] = [
        ("credential_path", |value| {
            value.nats_credentials_path = "/conf/alternate-store.credentials.json".to_string();
        }),
        ("credential_token", |value| {
            value.credential_invocation_token = "c".repeat(64);
        }),
        ("tls_url", |value| {
            value.nats_url = "tls://alternate.phase285.test:4222".to_string();
        }),
        ("tls_ca", |value| {
            value.tls_ca_path = "/conf/alternate-ca.pem".to_string();
        }),
        ("tls_server_name", |value| {
            value.tls_server_name = "alternate.phase285.test".to_string();
        }),
        ("subscription_capacity", |value| {
            value.subscription_capacity += 1;
        }),
        ("client_capacity", |value| value.client_capacity += 1),
        ("read_capacity", |value| value.read_buffer_capacity -= 1),
        ("deadline", |value| value.request_deadline_millis += 1),
        ("worker_capacities", |value| {
            value.ingress_queue_capacity += 1;
            value.max_in_flight += 1;
        }),
    ];
    for (label, mutate) in config_mutations {
        let mut service_config = config.clone();
        mutate(&mut service_config);
        assert_connection_service_ready_mismatch(
            label,
            &config,
            &ready,
            service_config,
            ready.clone(),
            entries.clone(),
        )
        .await?;
    }
    for (label, mutation) in [
        ("stream", ReadyBindingMutation::Stream),
        ("epoch", ReadyBindingMutation::Epoch),
        ("anchor", ReadyBindingMutation::Anchor),
        ("admission_set", ReadyBindingMutation::AdmissionSet),
        ("selected_limits", ReadyBindingMutation::SelectedLimits),
    ] {
        let (service_ready, service_entries) =
            store_ready_fixture_entries_with(&fixture, mutation)?;
        let service_config = store_service_config(&fixture, &service_ready)?;
        assert_connection_service_ready_mismatch(
            label,
            &config,
            &ready,
            service_config,
            service_ready,
            service_entries,
        )
        .await?;
    }
    let mut plaintext = config.clone();
    plaintext.nats_url = "nats://nats.phase285.test:4222".to_string();
    assert!(plaintext.validate_for_ready(&ready).is_err());
    for (path_variable, credential_role, capability) in [
        (
            "SWARM_NATS_RUNTIME_CREDENTIAL_PATH",
            "runtime",
            "runtime_credential_swap",
        ),
        (
            "SWARM_NATS_WITNESS_CREDENTIAL_PATH",
            "witness",
            "witness_credential_swap",
        ),
        (
            "SWARM_NATS_INIT_CREDENTIAL_PATH",
            "init",
            "init_credential_swap",
        ),
    ] {
        let mut mutant = config.clone();
        mutant.nats_credentials_path =
            std::env::var(path_variable).map_err(|_| ProtocolError::InvalidField {
                field: path_variable.to_string(),
                reason: "wrapped role credential is required".to_string(),
            })?;
        assert!(matches!(
            StoreRoleConnectionV1::connect(&mutant, &ready).await,
            Err(swarm_governance_witness::StoreProxyRunnerErrorV1::Configuration)
        ));
        write_capability_row(
            capability,
            credential_role,
            "PHASE285_WITNESS_STORE",
            "KV_phase285_service",
            "credential_role_refused",
            0,
            0,
        )?;
    }
    assert!(
        connect_harness_role("SWARM_NATS_STORE_CREDENTIAL_PATH", "witness")
            .await
            .is_err()
    );
    write_capability_row(
        "store_credential_swap",
        "witness-store",
        "PHASE285_WITNESS",
        store_proxy_subjects()[1],
        "cross_role_login_refused",
        0,
        0,
    )?;

    let account_swap = mutated_harness_credential(
        "SWARM_NATS_RUNTIME_CREDENTIAL_PATH",
        "account-swap",
        |credential| credential.role = "witness-store".to_string(),
    )?;
    let mut account_config = config.clone();
    account_config.nats_credentials_path = account_swap.to_string_lossy().into_owned();
    let (account_store, account_calls) = counting_store(ready.clone(), entries)?;
    let account_service =
        StoreProxyService::new(account_config.clone(), ready.clone(), account_store)
            .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    let account_connection = StoreRoleConnectionV1::connect(&account_config, &ready)
        .await
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    assert!(matches!(
        StoreProxyServiceRunner::start(account_connection, account_service).await,
        Err(swarm_governance_witness::StoreProxyRunnerErrorV1::Authentication)
    ));
    assert_eq!(account_calls.load(Ordering::SeqCst), 0);
    write_capability_row(
        "account_swap",
        "witness-store",
        "PHASE285_RUNTIME",
        "KV_phase285_service",
        "account_stream_probe_refused",
        0,
        0,
    )?;

    let mut ca_swap = config.clone();
    ca_swap.tls_ca_path = std::env::var("SWARM_NATS_RUNTIME_CREDENTIAL_PATH")
        .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
    assert!(matches!(
        StoreRoleConnectionV1::connect(&ca_swap, &ready).await,
        Err(swarm_governance_witness::StoreProxyRunnerErrorV1::Authentication)
    ));
    write_capability_row(
        "tls_ca_swap",
        "witness-store",
        "PHASE285_WITNESS_STORE",
        "tls://localhost",
        "ca_authentication_refused",
        0,
        0,
    )?;
    let mut name_swap = config.clone();
    name_swap.tls_server_name = "wrong.phase285.test".to_string();
    assert!(matches!(
        StoreRoleConnectionV1::connect(&name_swap, &ready).await,
        Err(swarm_governance_witness::StoreProxyRunnerErrorV1::Configuration)
    ));
    write_capability_row(
        "tls_server_name_swap",
        "witness-store",
        "PHASE285_WITNESS_STORE",
        "wrong.phase285.test",
        "server_name_refused",
        0,
        0,
    )?;
    let capacity_mutations: [fn(&mut StoreProxyServiceConfigV1); 3] = [
        |value: &mut StoreProxyServiceConfigV1| value.subscription_capacity = 0,
        |value: &mut StoreProxyServiceConfigV1| value.client_capacity = 0,
        |value: &mut StoreProxyServiceConfigV1| value.read_buffer_capacity = 0,
    ];
    for mutate in capacity_mutations {
        let mut bounded = config.clone();
        mutate(&mut bounded);
        assert!(bounded.validate_for_ready(&ready).is_err());
    }
    let compose = include_str!("../../../docker-compose.yml");
    assert!(compose.contains("phase285-runtime") && compose.contains("phase285-witness"));
    assert!(compose.contains("phase285-witness-store") && compose.contains("phase285-init"));
    assert!(compose.contains("cross-role-credential-mount"));
    write_capability_row(
        "mount_swap",
        "witness-store",
        "PHASE285_WITNESS_STORE",
        "raw-store-credentials",
        "cross_role_mount_absent",
        0,
        0,
    )
}

#[tokio::test]
async fn full_service_path_validates_proxy_response_before_public_attestation() -> ProtocolResult<()>
{
    let fixture = Fixture::new(CasMode::Apply)?;
    let (ready, entries) = store_ready_fixture_entries(&fixture)?;
    let (store, calls) = counting_store(ready.clone(), entries)?;
    let service = StoreProxyService::new(
        store_service_config(&fixture, &ready)?,
        ready.clone(),
        store,
    )
    .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    let request = signed_store_request(
        &fixture,
        &ready,
        WitnessStoreProxyOperationV1::ReadEntry,
        WitnessStoreProxyRequestBodyV1::ReadEntry {
            stream_id: fixture.admission.stream_id.clone(),
        },
    )?;
    let mut raw = canonical_wire_bytes(&request)?;
    raw.push(b' ');
    assert_eq!(
        service
            .handle_subject_bytes(store_proxy_subjects()[1], &raw)
            .await,
        Err(StoreProxyServiceErrorV1::Invalid)
    );
    let mut signature = request.clone();
    signature.signature.signature_hex = "0".repeat(128);
    assert_eq!(
        service
            .handle_subject_bytes(
                store_proxy_subjects()[1],
                &canonical_wire_bytes(&signature)?
            )
            .await,
        Err(StoreProxyServiceErrorV1::Invalid)
    );
    initialize_harness_store_stream().await?;
    let store_connection =
        StoreRoleConnectionV1::connect(&store_service_config(&fixture, &ready)?, &ready)
            .await
            .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    let witness_client =
        connect_harness_role("SWARM_NATS_WITNESS_CREDENTIAL_PATH", "witness").await?;
    let _runner = StoreProxyServiceRunner::start(store_connection, service)
        .await
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    witness_client
        .flush()
        .await
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    for (deadline_millis, accepted) in [
        (0, false),
        (2_999, false),
        (3_000, true),
        (3_001, false),
        (u64::MAX, false),
    ] {
        assert_eq!(
            NatsPublicWitnessStoreProxyClient::new(
                witness_client.clone(),
                MAX_PROTOCOL_RECORD_BYTES,
                MAX_PROTOCOL_RECORD_BYTES,
                deadline_millis,
            )
            .is_ok(),
            accepted,
            "private response grant constructor oracle differs at {deadline_millis}"
        );
    }
    let client = NatsPublicWitnessStoreProxyClient::new(
        witness_client.clone(),
        MAX_PROTOCOL_RECORD_BYTES,
        MAX_PROTOCOL_RECORD_BYTES,
        3_000,
    )
    .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    let response = client
        .read_entry(request)
        .await
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    assert!(matches!(
        response.body,
        WitnessStoreProxyResponseBodyV1::Entry { revision: 7, .. }
    ));
    let before = calls.load(Ordering::SeqCst);
    let valid_request = signed_store_request(
        &fixture,
        &ready,
        WitnessStoreProxyOperationV1::ReadEntry,
        WitnessStoreProxyRequestBodyV1::ReadEntry {
            stream_id: fixture.admission.stream_id.clone(),
        },
    )?;
    let mut injected: serde_json::Value =
        serde_json::from_slice(&canonical_wire_bytes(&valid_request)?)
            .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    injected
        .as_object_mut()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .insert(
            "reply_subject".to_string(),
            serde_json::Value::String("swarm.attacker.controlled.reply".to_string()),
        );
    assert_live_subject_refused(
        &witness_client,
        store_proxy_subjects()[1],
        &serde_json::to_vec(&injected)
            .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?,
    )
    .await?;
    let after = calls.load(Ordering::SeqCst);
    assert_eq!(after, before);
    write_capability_row(
        "reply_subject_injection",
        "witness",
        "PHASE285_WITNESS",
        store_proxy_subjects()[1],
        "invalid_reply_inbox",
        before,
        after,
    )?;
    let compose = include_str!("../../../docker-compose.yml");
    assert!(compose.contains("wildcard-service-import"));
    write_capability_row(
        "wildcard_import",
        "topology",
        "PHASE285_WITNESS",
        "swarm.governance.witness.store.v1.>",
        "wildcard_import_absent",
        0,
        0,
    )?;
    let service_source = include_str!("../src/store_proxy_service.rs");
    assert!(!service_source.contains("Ed25519Signer"));
    write_capability_row(
        "private_public_signing",
        "witness-store",
        "PHASE285_WITNESS_STORE",
        "StoreProxyService",
        "public_signer_absent",
        0,
        0,
    )
}

#[tokio::test]
async fn full_service_path_fails_closed_on_store_queue_exhaustion() -> ProtocolResult<()> {
    let (baseline, baseline_calls, request_bytes) = secondary_response_bytes_at_limit(None).await?;
    let baseline = baseline.map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    assert_eq!(baseline_calls, 1);
    assert!(request_bytes < MAX_PROTOCOL_RECORD_BYTES);
    let exact_limit =
        u64::try_from(baseline.len()).map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
    let (at_limit, at_limit_calls, _) =
        secondary_response_bytes_at_limit(Some(exact_limit)).await?;
    assert_eq!(
        at_limit
            .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?
            .len(),
        baseline.len()
    );
    assert_eq!(at_limit_calls, 1);
    let (over_limit, over_limit_calls, _) =
        secondary_response_bytes_at_limit(Some(exact_limit - 1)).await?;
    assert_eq!(over_limit, Err(StoreProxyServiceErrorV1::Bounds));
    assert_eq!(over_limit_calls, 1);

    let (baseline_overload, baseline_before, baseline_after, baseline_expected) =
        selected_overload_response_at_limit(MAX_PROTOCOL_RECORD_BYTES as u64).await?;
    assert_eq!(baseline_before, 1);
    assert_eq!(baseline_after, baseline_before);
    assert_eq!(baseline_overload, Some(baseline_expected.clone()));
    let overload_limit = u64::try_from(baseline_expected.len())
        .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
    let (exact_overload, exact_before, exact_after, exact_expected) =
        selected_overload_response_at_limit(overload_limit).await?;
    assert_eq!(exact_overload, Some(exact_expected));
    assert_eq!((exact_before, exact_after), (1, 1));
    let (bounded_overload, bounded_before, bounded_after, _) =
        selected_overload_response_at_limit(overload_limit - 1).await?;
    assert_eq!(bounded_overload, None);
    assert_eq!((bounded_before, bounded_after), (1, 1));

    let fixture = Fixture::new(CasMode::Apply)?;
    let (ready, entries) = store_ready_fixture_entries(&fixture)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let inner = InMemoryWitnessStore::new(ready.clone(), entries, 2_000_000)
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    let store = BlockingReadAtomicStore {
        inner,
        calls: calls.clone(),
        entered: entered.clone(),
        release: release.clone(),
    };
    let mut config = store_service_config(&fixture, &ready)?;
    config.ingress_queue_capacity = 1;
    config.max_in_flight = 1;
    let request = signed_store_request(
        &fixture,
        &ready,
        WitnessStoreProxyOperationV1::ReadEntry,
        WitnessStoreProxyRequestBodyV1::ReadEntry {
            stream_id: fixture.admission.stream_id.clone(),
        },
    )?;
    let request_bytes = canonical_wire_bytes(&request)?;
    let service = StoreProxyService::new(config.clone(), ready.clone(), store)
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    initialize_harness_store_stream().await?;
    let connection = StoreRoleConnectionV1::connect(&config, &ready)
        .await
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    let _runner = StoreProxyServiceRunner::start(connection, service)
        .await
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    let client = connect_harness_role("SWARM_NATS_WITNESS_CREDENTIAL_PATH", "witness").await?;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let first_client = client.clone();
    let first_bytes = request_bytes.clone();
    let first = tokio::spawn(async move {
        first_client
            .request(store_proxy_subjects()[1], first_bytes.into())
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), entered.notified())
        .await
        .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
    let second_client = client.clone();
    let second_bytes = request_bytes.clone();
    let second = tokio::spawn(async move {
        second_client
            .request(store_proxy_subjects()[1], second_bytes.into())
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(75)).await;
    let before = calls.load(Ordering::SeqCst);
    assert_eq!(before, 1);
    let overload = client
        .request(store_proxy_subjects()[1], request_bytes.into())
        .await
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    let overload = WitnessStoreProxyResponseV1::decode(&overload.payload)?;
    assert!(matches!(
        overload.body,
        WitnessStoreProxyResponseBodyV1::Refused {
            failure_code: WitnessStoreProxyFailureCodeV1::Unavailable,
            observed_revision: None,
            observed_value_digest: None,
        }
    ));
    let after = calls.load(Ordering::SeqCst);
    assert_eq!(after, before);
    release.notify_waiters();
    first
        .await
        .map_err(join_error)?
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    second
        .await
        .map_err(join_error)?
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    assert!(private_store_ingress_overload_control());
    write_capability_row(
        "store_queue_exhaustion",
        "witness",
        "PHASE285_WITNESS",
        store_proxy_subjects()[1],
        "overload_unavailable",
        before,
        after,
    )?;
    assert_eq!(
        store_proxy_subjects(),
        &[
            "swarm.governance.witness.store.v1.inspect_ready",
            "swarm.governance.witness.store.v1.read_entry",
            "swarm.governance.witness.store.v1.compare_and_swap",
        ]
    );
    let service_source = include_str!("../src/store_proxy_service.rs");
    assert!(!service_source.contains("$KV.") && !service_source.contains("$JS.API."));
    write_capability_row(
        "public_store_bypass",
        "runtime",
        "PHASE285_RUNTIME",
        "StoreProxyService",
        "raw_store_api_absent",
        0,
        0,
    )?;
    let harness = include_str!("../../../tools/with-nats-jetstream.sh");
    assert!(harness.contains("cleanup_confined_scratch"));
    assert!(harness.contains("paths_overlap"));
    write_capability_row(
        "hostile_cleanup_preservation",
        "harness",
        "confined-project",
        "cleanup_confined_scratch",
        "cleanup_fail_closed",
        0,
        0,
    )
}
