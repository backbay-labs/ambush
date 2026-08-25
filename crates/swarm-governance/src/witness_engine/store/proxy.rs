//! Canonical request validator and typed proxy over [`WitnessAtomicStore`].

use super::{
    WitnessAtomicStore, WitnessStoreCasResultV1, WitnessStoreErrorV1,
    WitnessStoreProxyRequestBodyV1, WitnessStoreProxyRequestV1, WitnessStoreProxyResponseBodyV1,
    WitnessStoreProxyResponseV1, WitnessStoreReadResultV1, WitnessStoreReadyResultV1,
    validate_cas_transition, validate_read_entry,
};
use crate::persistence_protocol::{
    MAX_PROTOCOL_RECORD_BYTES, PROTOCOL_SCHEMA_VERSION, ProtocolError, canonical_wire_bytes,
};

#[derive(Debug)]
pub struct WitnessStoreProxy<S> {
    store: S,
    configured_ready: WitnessStoreReadyResultV1,
}

impl<S: WitnessAtomicStore> WitnessStoreProxy<S> {
    pub fn new(
        store: S,
        configured_ready: WitnessStoreReadyResultV1,
    ) -> Result<Self, WitnessStoreErrorV1> {
        configured_ready
            .validate()
            .map_err(super::classify_protocol_error)?;
        Ok(Self {
            store,
            configured_ready,
        })
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub async fn handle_bytes(
        &self,
        raw: &[u8],
    ) -> Result<WitnessStoreProxyResponseV1, WitnessStoreErrorV1> {
        // 1. Bound before decode/allocation.
        if raw.len() > MAX_PROTOCOL_RECORD_BYTES {
            return Err(WitnessStoreErrorV1::Bounds);
        }
        // 2-4. Canonical decode, operation/body pairing, and digest.
        let request = WitnessStoreProxyRequestV1::decode(raw).map_err(map_request_error)?;
        // 5. Pinned witness signature.
        request
            .validate_signature()
            .map_err(|_| WitnessStoreErrorV1::Signature)?;
        request.validate_semantics().map_err(map_request_error)?;
        // 6. Request-only epoch/anchor/admission/mapping/limit checks.
        let admission = self.validate_request_namespace(&request, raw.len())?;
        let max_response_bytes = admission.max_response_bytes;

        let result = match &request.body {
            WitnessStoreProxyRequestBodyV1::InspectReady => {
                let backend = self.store.inspect_ready().await;
                match backend {
                    Ok(ready) if same_ready_contract(&ready, &self.configured_ready) => {
                        let mut stream_ids = ready
                            .admission_set
                            .entries
                            .iter()
                            .map(|entry| entry.stream_id.clone())
                            .collect::<Vec<_>>();
                        stream_ids.sort();
                        stream_ids.dedup();
                        if stream_ids.len() != ready.admission_set.entries.len() {
                            return bounded_response(
                                refused(&request, WitnessStoreErrorV1::Admission, None, None),
                                max_response_bytes,
                            );
                        }
                        let mut validated_streams = std::collections::BTreeMap::new();
                        for stream_id in stream_ids {
                            let observed = match self.store.read_entry(&stream_id).await {
                                Ok(WitnessStoreReadResultV1::Entry {
                                    stream_id: observed_stream,
                                    revision,
                                    envelope,
                                }) if observed_stream == stream_id => {
                                    let validated = match validate_read_entry(
                                        &self.configured_ready,
                                        &stream_id,
                                        revision,
                                        &envelope,
                                    ) {
                                        Ok(value) => value,
                                        Err(error) => {
                                            return bounded_response(
                                                refused(&request, error, Some(revision), None),
                                                max_response_bytes,
                                            );
                                        }
                                    };
                                    (observed_stream, validated)
                                }
                                Ok(WitnessStoreReadResultV1::Entry { revision, .. }) => {
                                    return bounded_response(
                                        refused(
                                            &request,
                                            WitnessStoreErrorV1::Corrupt,
                                            Some(revision),
                                            None,
                                        ),
                                        max_response_bytes,
                                    );
                                }
                                Err(error) => {
                                    return bounded_response(
                                        refused(&request, error, None, None),
                                        max_response_bytes,
                                    );
                                }
                            };
                            if validated_streams.insert(observed.0, observed.1).is_some() {
                                return bounded_response(
                                    refused(&request, WitnessStoreErrorV1::Corrupt, None, None),
                                    max_response_bytes,
                                );
                            }
                        }
                        if validated_streams.len() != ready.admission_set.entries.len() {
                            return bounded_response(
                                refused(&request, WitnessStoreErrorV1::Missing, None, None),
                                max_response_bytes,
                            );
                        }
                        Ok(response(
                            &request,
                            WitnessStoreProxyResponseBodyV1::Ready {
                                nats_stream_created_at: ready.nats_stream_created_at,
                                bucket_configuration_digest: ready
                                    .bucket_epoch
                                    .bucket_configuration_digest,
                                ready_manifest: Box::new(ready.ready_manifest),
                                validated_streams,
                            },
                        ))
                    }
                    Ok(_) => Ok(refused(
                        &request,
                        WitnessStoreErrorV1::Configuration,
                        None,
                        None,
                    )),
                    Err(error) => Ok(refused(&request, error, None, None)),
                }
            }
            WitnessStoreProxyRequestBodyV1::ReadEntry { stream_id } => {
                match self.store.read_entry(stream_id).await {
                    Ok(WitnessStoreReadResultV1::Entry {
                        stream_id: observed_stream,
                        revision,
                        envelope,
                    }) => {
                        if observed_stream != *stream_id || revision == 0 {
                            return bounded_response(
                                refused(
                                    &request,
                                    WitnessStoreErrorV1::Corrupt,
                                    Some(revision),
                                    None,
                                ),
                                max_response_bytes,
                            );
                        }
                        if let Err(error) = validate_read_entry(
                            &self.configured_ready,
                            stream_id,
                            revision,
                            &envelope,
                        ) {
                            return bounded_response(
                                refused(&request, error, Some(revision), None),
                                max_response_bytes,
                            );
                        }
                        Ok(response(
                            &request,
                            WitnessStoreProxyResponseBodyV1::Entry {
                                stream_id: observed_stream,
                                revision,
                                envelope,
                            },
                        ))
                    }
                    Err(error) => Ok(refused(&request, error, None, None)),
                }
            }
            WitnessStoreProxyRequestBodyV1::CompareAndSwap {
                stream_id,
                expected_revision,
                expected_store_state_digest,
                proposed_envelope,
            } => {
                // 7. Authenticated read.
                let current = match self.store.read_entry(stream_id).await {
                    Ok(WitnessStoreReadResultV1::Entry {
                        stream_id: observed_stream,
                        revision,
                        envelope,
                    }) if observed_stream == *stream_id => (revision, envelope),
                    Ok(WitnessStoreReadResultV1::Entry { revision, .. }) => {
                        return bounded_response(
                            refused(&request, WitnessStoreErrorV1::Corrupt, Some(revision), None),
                            max_response_bytes,
                        );
                    }
                    Err(error) => {
                        return bounded_response(
                            refused(&request, error, None, None),
                            max_response_bytes,
                        );
                    }
                };
                // 8-9. Exact revision/current digest and complete proposed
                // envelope plus one-step transition validation.
                let proposed_value_digest = match validate_cas_transition(
                    &self.configured_ready,
                    stream_id,
                    *expected_revision,
                    expected_store_state_digest,
                    current.0,
                    &current.1,
                    proposed_envelope,
                ) {
                    Ok(value) => value,
                    Err(error) => {
                        let observed_digest = current.1.store_state_digest().ok();
                        return bounded_response(
                            refused(&request, error, Some(current.0), observed_digest),
                            max_response_bytes,
                        );
                    }
                };
                // 10. CAS.
                let cas = match self
                    .store
                    .compare_and_swap(
                        stream_id,
                        *expected_revision,
                        expected_store_state_digest,
                        proposed_envelope,
                    )
                    .await
                {
                    Ok(value) => value,
                    Err(error) => {
                        let (revision, digest, proved_non_application) = authenticated_diagnostic(
                            &self.configured_ready,
                            stream_id,
                            self.store.read_entry(stream_id).await,
                            current.0,
                            &current.1,
                        );
                        return bounded_response(
                            refused(
                                &request,
                                if proved_non_application {
                                    error
                                } else {
                                    WitnessStoreErrorV1::Ambiguous
                                },
                                revision,
                                digest,
                            ),
                            max_response_bytes,
                        );
                    }
                };
                match cas {
                    WitnessStoreCasResultV1::Applied {
                        stream_id: ack_stream,
                        expected_previous_revision,
                        previous_revision,
                        new_revision,
                        acknowledged_value_digest,
                        duplicate,
                    } => {
                        if ack_stream != *stream_id
                            || expected_previous_revision != *expected_revision
                            || previous_revision != current.0
                            || new_revision <= current.0
                            || duplicate
                            || acknowledged_value_digest != proposed_value_digest
                        {
                            let diagnostic = self.store.read_entry(stream_id).await;
                            let (revision, digest, proved_non_application) =
                                authenticated_diagnostic(
                                    &self.configured_ready,
                                    stream_id,
                                    diagnostic,
                                    current.0,
                                    &current.1,
                                );
                            return bounded_response(
                                refused(
                                    &request,
                                    if proved_non_application {
                                        WitnessStoreErrorV1::Corrupt
                                    } else {
                                        WitnessStoreErrorV1::Ambiguous
                                    },
                                    revision,
                                    digest,
                                ),
                                max_response_bytes,
                            );
                        }
                        // 11. Exact confirmation read. An Applied ack is not
                        // exposed unless revision, canonical bytes, and digest
                        // all match the exact proposed value.
                        match self.store.read_entry(stream_id).await {
                            Ok(WitnessStoreReadResultV1::Entry {
                                stream_id: confirmed_stream,
                                revision: confirmed_revision,
                                envelope: confirmed,
                            }) if confirmed_stream == *stream_id
                                && confirmed_revision == new_revision
                                && canonical_wire_bytes(confirmed.as_ref()).ok()
                                    == canonical_wire_bytes(proposed_envelope.as_ref()).ok()
                                && confirmed.signed_envelope_digest().ok()
                                    == Some(proposed_value_digest.clone()) =>
                            {
                                Ok(response(
                                    &request,
                                    WitnessStoreProxyResponseBodyV1::CasApplied {
                                        stream_id: stream_id.clone(),
                                        previous_revision,
                                        new_revision,
                                        acknowledged_value_digest,
                                    },
                                ))
                            }
                            Ok(WitnessStoreReadResultV1::Entry {
                                revision, envelope, ..
                            }) => {
                                let valid = validate_read_entry(
                                    &self.configured_ready,
                                    stream_id,
                                    revision,
                                    &envelope,
                                )
                                .is_ok();
                                let proved_non_application = valid
                                    && revision == current.0
                                    && canonical_wire_bytes(envelope.as_ref()).ok()
                                        == canonical_wire_bytes(current.1.as_ref()).ok();
                                Ok(refused(
                                    &request,
                                    if proved_non_application {
                                        WitnessStoreErrorV1::Corrupt
                                    } else {
                                        WitnessStoreErrorV1::Ambiguous
                                    },
                                    valid.then_some(revision),
                                    valid
                                        .then(|| envelope.signed_envelope_digest().ok())
                                        .flatten(),
                                ))
                            }
                            Err(_) => Ok(refused(
                                &request,
                                WitnessStoreErrorV1::Ambiguous,
                                None,
                                None,
                            )),
                        }
                    }
                    WitnessStoreCasResultV1::Conflict {
                        stream_id: observed_stream,
                        observed_revision,
                        observed_envelope,
                    } => {
                        if observed_stream != *stream_id
                            || observed_revision == 0
                            || validate_read_entry(
                                &self.configured_ready,
                                stream_id,
                                observed_revision,
                                &observed_envelope,
                            )
                            .is_err()
                        {
                            return bounded_response(
                                refused(
                                    &request,
                                    WitnessStoreErrorV1::Corrupt,
                                    Some(observed_revision),
                                    None,
                                ),
                                max_response_bytes,
                            );
                        }
                        Ok(response(
                            &request,
                            WitnessStoreProxyResponseBodyV1::Conflict {
                                stream_id: observed_stream,
                                observed_revision,
                                observed_envelope,
                            },
                        ))
                    }
                    WitnessStoreCasResultV1::Ambiguous {
                        stream_id: ambiguous_stream,
                        expected_previous_revision,
                        observed_revision: backend_revision,
                        observed_value_digest: backend_digest,
                    } => {
                        // A matching diagnostic read is evidence for the later
                        // fenced resolver, never authority to upgrade or retry.
                        let metadata_valid = ambiguous_stream == *stream_id
                            && expected_previous_revision == *expected_revision
                            && backend_revision != Some(0)
                            && backend_digest.as_ref().is_none_or(|digest| {
                                digest.len() == 64
                                    && digest.bytes().all(|byte| {
                                        byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
                                    })
                            });
                        let (observed_revision, observed_value_digest, _) =
                            authenticated_diagnostic(
                                &self.configured_ready,
                                stream_id,
                                self.store.read_entry(stream_id).await,
                                current.0,
                                &current.1,
                            );
                        Ok(refused(
                            &request,
                            WitnessStoreErrorV1::Ambiguous,
                            metadata_valid.then_some(observed_revision).flatten(),
                            metadata_valid.then_some(observed_value_digest).flatten(),
                        ))
                    }
                }
            }
        }?;
        bounded_response(result, max_response_bytes)
    }

    fn validate_request_namespace<'a>(
        &'a self,
        request: &WitnessStoreProxyRequestV1,
        raw_len: usize,
    ) -> Result<&'a super::WitnessAdmissionEntryV1, WitnessStoreErrorV1> {
        if request.bucket_epoch_digest
            != self
                .configured_ready
                .bucket_epoch
                .digest()
                .map_err(super::classify_protocol_error)?
            || request.bucket_anchor_digest
                != self
                    .configured_ready
                    .bucket_anchor
                    .digest()
                    .map_err(super::classify_protocol_error)?
            || request.witness_key_id != self.configured_ready.bucket_epoch.witness_key_id
        {
            return Err(WitnessStoreErrorV1::Configuration);
        }
        let admission = match &request.body {
            WitnessStoreProxyRequestBodyV1::ReadEntry { stream_id }
            | WitnessStoreProxyRequestBodyV1::CompareAndSwap { stream_id, .. } => self
                .configured_ready
                .entry(stream_id)
                .ok_or(WitnessStoreErrorV1::Admission)?,
            WitnessStoreProxyRequestBodyV1::InspectReady => self
                .configured_ready
                .admission_set
                .entries
                .iter()
                .find(|entry| entry.admission_digest == request.admission_digest)
                .ok_or(WitnessStoreErrorV1::Admission)?,
        };
        if request.admission_digest != admission.admission_digest {
            return Err(WitnessStoreErrorV1::Admission);
        }
        if raw_len as u64 > admission.max_request_bytes {
            return Err(WitnessStoreErrorV1::Bounds);
        }
        if let WitnessStoreProxyRequestBodyV1::CompareAndSwap {
            stream_id,
            proposed_envelope,
            ..
        } = &request.body
        {
            let expected_key = super::super::witness_stream_key(stream_id)
                .map_err(super::classify_protocol_error)?;
            if !self
                .configured_ready
                .ready_manifest
                .stream_keys
                .contains(&expected_key)
                || canonical_wire_bytes(proposed_envelope.as_ref())
                    .map_err(super::classify_protocol_error)?
                    .len() as u64
                    > admission.max_retained_bytes
            {
                return Err(WitnessStoreErrorV1::Bounds);
            }
        }
        Ok(admission)
    }
}

fn same_ready_contract(
    observed: &WitnessStoreReadyResultV1,
    configured: &WitnessStoreReadyResultV1,
) -> bool {
    observed.schema_version == configured.schema_version
        && observed.nats_stream_created_at == configured.nats_stream_created_at
        && observed.bucket_configuration == configured.bucket_configuration
        && observed.bucket_epoch == configured.bucket_epoch
        && observed.bucket_anchor == configured.bucket_anchor
        && observed.admission_set == configured.admission_set
        && observed.ready_manifest == configured.ready_manifest
        && observed.deployment_inputs == configured.deployment_inputs
        && observed.validate().is_ok()
}

fn response(
    request: &WitnessStoreProxyRequestV1,
    body: WitnessStoreProxyResponseBodyV1,
) -> WitnessStoreProxyResponseV1 {
    WitnessStoreProxyResponseV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        operation: request.operation,
        request_digest: request.request_digest.clone(),
        body,
    }
}

fn bounded_response(
    response: WitnessStoreProxyResponseV1,
    maximum: u64,
) -> Result<WitnessStoreProxyResponseV1, WitnessStoreErrorV1> {
    let length = canonical_wire_bytes(&response)
        .map_err(super::classify_protocol_error)?
        .len() as u64;
    if length > maximum {
        return Err(WitnessStoreErrorV1::Bounds);
    }
    Ok(response)
}

fn authenticated_diagnostic(
    ready: &WitnessStoreReadyResultV1,
    stream_id: &str,
    result: Result<WitnessStoreReadResultV1, WitnessStoreErrorV1>,
    prior_revision: u64,
    prior: &super::WitnessStoreEnvelopeV1,
) -> (Option<u64>, Option<String>, bool) {
    let Ok(WitnessStoreReadResultV1::Entry {
        stream_id: observed_stream,
        revision,
        envelope,
    }) = result
    else {
        return (None, None, false);
    };
    if observed_stream != stream_id
        || validate_read_entry(ready, stream_id, revision, &envelope).is_err()
    {
        return (None, None, false);
    }
    let digest = envelope.signed_envelope_digest().ok();
    let unchanged = revision == prior_revision
        && canonical_wire_bytes(envelope.as_ref()).ok() == canonical_wire_bytes(prior).ok();
    (Some(revision), digest, unchanged)
}

fn refused(
    request: &WitnessStoreProxyRequestV1,
    error: WitnessStoreErrorV1,
    observed_revision: Option<u64>,
    observed_value_digest: Option<String>,
) -> WitnessStoreProxyResponseV1 {
    response(
        request,
        WitnessStoreProxyResponseBodyV1::Refused {
            failure_code: error.failure_code(),
            observed_revision,
            observed_value_digest,
        },
    )
}

fn map_request_error(error: ProtocolError) -> WitnessStoreErrorV1 {
    match error {
        ProtocolError::Bounds { .. } => WitnessStoreErrorV1::Bounds,
        ProtocolError::CanonicalEncoding(_) | ProtocolError::NonCanonicalEncoding => {
            WitnessStoreErrorV1::Corrupt
        }
        _ => WitnessStoreErrorV1::Admission,
    }
}
