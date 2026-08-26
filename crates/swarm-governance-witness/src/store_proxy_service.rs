use async_trait::async_trait;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use swarm_governance::persistence_protocol::{PROTOCOL_SCHEMA_VERSION, canonical_wire_bytes};
use swarm_governance::witness_engine::store::proxy::WitnessStoreProxy;
use swarm_governance::witness_engine::store::{
    WitnessAtomicStore, WitnessStoreErrorV1, WitnessStoreProxyFailureCodeV1,
    WitnessStoreProxyOperationV1, WitnessStoreProxyRequestV1, WitnessStoreProxyResponseBodyV1,
    WitnessStoreProxyResponseV1, WitnessStoreReadyResultV1,
};
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Duration, timeout};

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
        })
    }

    pub async fn handle_subject_bytes(
        &self,
        subject: &str,
        raw: &[u8],
    ) -> Result<Vec<u8>, StoreProxyServiceErrorV1> {
        if raw.len() > self.config.max_request_bytes {
            return Err(StoreProxyServiceErrorV1::Bounds);
        }
        let selected = self.preflight(subject, raw)?;
        let response = timeout(
            Duration::from_millis(self.config.request_deadline_millis),
            self.proxy.handle_bytes(raw),
        )
        .await
        .map_err(|_| StoreProxyServiceErrorV1::Timeout)?
        .map_err(map_store_error)?;
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

fn map_store_error(error: WitnessStoreErrorV1) -> StoreProxyServiceErrorV1 {
    match error {
        WitnessStoreErrorV1::Bounds => StoreProxyServiceErrorV1::Bounds,
        WitnessStoreErrorV1::Unavailable | WitnessStoreErrorV1::Ambiguous => {
            StoreProxyServiceErrorV1::Unavailable
        }
        _ => StoreProxyServiceErrorV1::Invalid,
    }
}

struct PrivateIngressMessage {
    subject: String,
    payload: Vec<u8>,
    reply: async_nats::Subject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StoreProxyRunnerErrorV1 {
    #[error("private proxy transport configuration failed")]
    Configuration,
    #[error("private proxy transport authentication failed")]
    Authentication,
    #[error("private proxy subscription setup failed")]
    Subscription,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
}

impl StoreRoleConnectionV1 {
    pub async fn connect(
        config: &StoreProxyServiceConfigV1,
        ready: &WitnessStoreReadyResultV1,
    ) -> Result<Self, StoreProxyRunnerErrorV1> {
        let ready_binding = StoreProxyReadyBindingV1::validated(config, ready)
            .map_err(|_| StoreProxyRunnerErrorV1::Configuration)?;
        let authority =
            tls_authority(&config.nats_url).ok_or(StoreProxyRunnerErrorV1::Configuration)?;
        if authority != config.tls_server_name {
            return Err(StoreProxyRunnerErrorV1::Configuration);
        }
        let raw = tokio::fs::read(&config.nats_credentials_path)
            .await
            .map_err(|_| StoreProxyRunnerErrorV1::Configuration)?;
        if raw.is_empty() || raw.len() > 4_096 {
            return Err(StoreProxyRunnerErrorV1::Configuration);
        }
        let credentials: StoreRoleCredentialFileV1 =
            serde_json::from_slice(&raw).map_err(|_| StoreProxyRunnerErrorV1::Configuration)?;
        let canonical =
            serde_json::to_vec(&credentials).map_err(|_| StoreProxyRunnerErrorV1::Configuration)?;
        if canonical != raw
            || credentials.schema_version != PROTOCOL_SCHEMA_VERSION
            || credentials.role != "witness-store"
            || credentials.invocation_token != config.credential_invocation_token
            || credentials.username.is_empty()
            || credentials.password.is_empty()
        {
            return Err(StoreProxyRunnerErrorV1::Configuration);
        }
        let options = async_nats::ConnectOptions::with_user_and_password(
            credentials.username,
            credentials.password,
        )
        .require_tls(true)
        .add_root_certificates(PathBuf::from(&config.tls_ca_path))
        .subscription_capacity(config.subscription_capacity)
        .client_capacity(config.client_capacity)
        .read_buffer_capacity(config.read_buffer_capacity)
        .connection_timeout(Duration::from_millis(config.request_deadline_millis))
        .request_timeout(Some(Duration::from_millis(config.request_deadline_millis)))
        .max_reconnects(Some(1));
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
        })
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
    _service: std::marker::PhantomData<S>,
}

impl<S: WitnessAtomicStore + 'static> StoreProxyServiceRunner<S> {
    pub async fn start(
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
            tasks.push(tokio::spawn(async move {
                let mut subscriber = subscriber;
                while let Some(message) = subscriber.next().await {
                    let Some(reply) = message.reply else { continue };
                    if !bounded_inbox(&reply) {
                        continue;
                    }
                    let ingress = PrivateIngressMessage {
                        subject: subject.to_string(),
                        payload: message.payload.to_vec(),
                        reply: reply.clone(),
                    };
                    if sender.try_send(ingress).is_err()
                        && let Some(bytes) = service.overload_response(subject, &message.payload)
                    {
                        let _ = client.publish(reply, bytes.into()).await;
                    }
                }
            }));
        }
        drop(sender);
        for _ in 0..worker_count {
            let receiver = receiver.clone();
            let service = service.clone();
            let client = client.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    let message = {
                        let mut guard = receiver.lock().await;
                        guard.recv().await
                    };
                    let Some(message) = message else { break };
                    if let Ok(bytes) = service
                        .handle_subject_bytes(&message.subject, &message.payload)
                        .await
                    {
                        let _ = client.publish(message.reply, bytes.into()).await;
                    }
                }
            }));
        }
        Ok(Self {
            tasks,
            _service: std::marker::PhantomData,
        })
    }
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
    request_deadline_millis: u64,
}

impl NatsPublicWitnessStoreProxyClient {
    pub fn new(
        client: async_nats::Client,
        max_request_bytes: usize,
        max_response_bytes: usize,
        request_deadline_millis: u64,
    ) -> Result<Self, PublicWitnessProxyTransportErrorV1> {
        if max_request_bytes == 0 || max_response_bytes == 0 || request_deadline_millis == 0 {
            return Err(PublicWitnessProxyTransportErrorV1::Framing);
        }
        Ok(Self {
            client,
            max_request_bytes,
            max_response_bytes,
            request_deadline_millis,
        })
    }

    async fn request(
        &self,
        request: WitnessStoreProxyRequestV1,
        operation: WitnessStoreProxyOperationV1,
    ) -> Result<WitnessStoreProxyResponseV1, PublicWitnessProxyTransportErrorV1> {
        if request.operation != operation {
            return Err(PublicWitnessProxyTransportErrorV1::Framing);
        }
        let request_digest = request.request_digest.clone();
        let bytes = canonical_wire_bytes(&request)
            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;
        if bytes.len() > self.max_request_bytes {
            return Err(PublicWitnessProxyTransportErrorV1::Framing);
        }
        let message = timeout(
            Duration::from_millis(self.request_deadline_millis),
            self.client.request(subject_for(operation), bytes.into()),
        )
        .await
        .map_err(|_| PublicWitnessProxyTransportErrorV1::Timeout)?
        .map_err(|_| PublicWitnessProxyTransportErrorV1::Unavailable)?;
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
