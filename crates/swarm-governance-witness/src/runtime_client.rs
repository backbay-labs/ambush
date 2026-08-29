use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
use std::time::Instant;
use swarm_governance::persistence_protocol::{
    GovernanceDurabilityWitness, MAX_PROTOCOL_STRING_BYTES, PROTOCOL_SCHEMA_VERSION,
    WitnessDiscoveryAttestationV1, WitnessOutcomeAttestationV1, WitnessReadAttestationV1,
    WitnessSessionAttestationV1, WitnessSessionStateFenceV1,
};
use swarm_governance::witness_service::{
    WitnessServiceFailureAttestationV1, WitnessServiceRequestV1, WitnessServiceResponseV1,
};
use tokio::time::{Duration, timeout};

use swarm_crypto::Ed25519Signer;

use crate::raw_config::relay_topology_token_is_closed;
use crate::service_config::{PUBLIC_RESPONSE_GRANT_MILLIS, STORE_RESPONSE_GRANT_MILLIS};
use crate::{
    NatsPublicWitnessStoreProxyClient, NatsWitnessStore, PublicWitnessDispatcher,
    PublicWitnessProcessConfigV1, PublicWitnessServiceConfigV1, PublicWitnessServiceRunner,
    RuntimeWitnessClientConfigV1, StoreProxyProcessConfigV1, StoreProxyService,
    StoreProxyServiceRunner, StoreRoleConnectionV1,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeRoleCredentialFileV1 {
    schema_version: u32,
    role: String,
    username: String,
    password: String,
    invocation_token: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeWitnessClientErrorV1 {
    #[error("runtime witness client configuration is invalid")]
    Configuration,
    #[error("runtime witness transport authentication failed")]
    Authentication,
    #[error("runtime witness request exceeds its configured bound")]
    RequestBounds,
    #[error("runtime witness response exceeds its configured bound")]
    ResponseBounds,
    #[error("runtime witness transport is unavailable")]
    Unavailable,
    #[error("runtime witness request timed out with unknown outcome")]
    OutcomeUnknown,
    #[error("runtime witness response is invalid")]
    InvalidResponse,
    #[error("runtime witness returned a signed application refusal")]
    Application(Box<WitnessServiceFailureAttestationV1>),
}

#[derive(Debug, thiserror::Error)]
pub enum WitnessProcessErrorV1 {
    #[error("service process configuration is invalid")]
    Configuration,
    #[error("service process authentication failed")]
    Authentication,
    #[error("service process startup failed")]
    Startup,
}

fn map_request_error_kind(kind: async_nats::RequestErrorKind) -> RuntimeWitnessClientErrorV1 {
    match kind {
        async_nats::RequestErrorKind::TimedOut => RuntimeWitnessClientErrorV1::OutcomeUnknown,
        async_nats::RequestErrorKind::Other => RuntimeWitnessClientErrorV1::OutcomeUnknown,
        async_nats::RequestErrorKind::NoResponders => RuntimeWitnessClientErrorV1::Unavailable,
        async_nats::RequestErrorKind::InvalidSubject => RuntimeWitnessClientErrorV1::Configuration,
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeRequestObservationV1 {
    Response,
    TimedOut,
    NoResponders,
    InvalidSubject,
    Other,
}

#[cfg(test)]
impl From<async_nats::RequestErrorKind> for RuntimeRequestObservationV1 {
    fn from(value: async_nats::RequestErrorKind) -> Self {
        match value {
            async_nats::RequestErrorKind::TimedOut => Self::TimedOut,
            async_nats::RequestErrorKind::NoResponders => Self::NoResponders,
            async_nats::RequestErrorKind::InvalidSubject => Self::InvalidSubject,
            async_nats::RequestErrorKind::Other => Self::Other,
        }
    }
}

struct RoleTransportConfigV1<'a> {
    nats_url: &'a str,
    credentials_path: &'a str,
    invocation_token: &'a str,
    tls_ca_path: &'a str,
    tls_server_name: &'a str,
    role: &'static str,
    subscription_capacity: usize,
    client_capacity: usize,
    read_buffer_capacity: u16,
    deadline_millis: u64,
}

fn tls_authority(url: &str) -> Option<&str> {
    let authority = url.strip_prefix("tls://")?;
    if authority.contains(['@', '/', '?']) {
        return None;
    }
    authority.rsplit_once(':').map(|(host, _)| host)
}

async fn connect_exact_role(
    config: RoleTransportConfigV1<'_>,
) -> Result<async_nats::Client, RuntimeWitnessClientErrorV1> {
    if config.deadline_millis == 0 || tls_authority(config.nats_url) != Some(config.tls_server_name)
    {
        return Err(RuntimeWitnessClientErrorV1::Configuration);
    }
    let raw = tokio::fs::read(config.credentials_path)
        .await
        .map_err(|_| RuntimeWitnessClientErrorV1::Configuration)?;
    if raw.is_empty() || raw.len() > 4_096 {
        return Err(RuntimeWitnessClientErrorV1::Configuration);
    }
    let credentials: RuntimeRoleCredentialFileV1 =
        serde_json::from_slice(&raw).map_err(|_| RuntimeWitnessClientErrorV1::Configuration)?;
    let canonical =
        serde_json::to_vec(&credentials).map_err(|_| RuntimeWitnessClientErrorV1::Configuration)?;
    if canonical != raw
        || credentials.schema_version != PROTOCOL_SCHEMA_VERSION
        || credentials.role != config.role
        || credentials.invocation_token != config.invocation_token
        || credentials.username.is_empty()
        || credentials.password.is_empty()
        || credentials.username.len() > MAX_PROTOCOL_STRING_BYTES
        || credentials.password.len() > MAX_PROTOCOL_STRING_BYTES
    {
        return Err(RuntimeWitnessClientErrorV1::Configuration);
    }
    let options = async_nats::ConnectOptions::with_user_and_password(
        credentials.username,
        credentials.password,
    )
    .require_tls(true)
    .add_root_certificates(PathBuf::from(config.tls_ca_path))
    .subscription_capacity(config.subscription_capacity)
    .client_capacity(config.client_capacity)
    .read_buffer_capacity(config.read_buffer_capacity)
    .connection_timeout(Duration::from_millis(config.deadline_millis))
    .request_timeout(Some(Duration::from_millis(config.deadline_millis)))
    .max_reconnects(Some(1));
    let client = timeout(
        Duration::from_millis(config.deadline_millis),
        options.connect(config.nats_url),
    )
    .await
    .map_err(|_| RuntimeWitnessClientErrorV1::Authentication)?
    .map_err(|_| RuntimeWitnessClientErrorV1::Authentication)?;
    timeout(
        Duration::from_millis(config.deadline_millis),
        client.flush(),
    )
    .await
    .map_err(|_| RuntimeWitnessClientErrorV1::Authentication)?
    .map_err(|_| RuntimeWitnessClientErrorV1::Authentication)?;
    Ok(client)
}

pub async fn run_public_witness_process(
    config: PublicWitnessProcessConfigV1,
) -> Result<(), WitnessProcessErrorV1> {
    if let Ok(token) = std::env::var("PHASE285_RELAY_TOPOLOGY_TOKEN")
        && !relay_topology_token_is_closed(&token)
    {
        return Err(WitnessProcessErrorV1::Configuration);
    }
    config
        .validate()
        .map_err(|_| WitnessProcessErrorV1::Configuration)?;
    let client = connect_exact_role(RoleTransportConfigV1 {
        nats_url: &config.service.nats_url,
        credentials_path: &config.service.nats_credentials_path,
        invocation_token: &config.credential_invocation_token,
        tls_ca_path: &config.service.tls_ca_path,
        tls_server_name: &config.service.tls_server_name,
        role: "witness",
        subscription_capacity: config.subscription_capacity,
        client_capacity: config.client_capacity,
        read_buffer_capacity: config.read_buffer_capacity,
        deadline_millis: PUBLIC_RESPONSE_GRANT_MILLIS,
    })
    .await
    .map_err(|_| WitnessProcessErrorV1::Authentication)?;
    let secret = tokio::fs::read_to_string(&config.service.witness_key_path)
        .await
        .map_err(|_| WitnessProcessErrorV1::Configuration)?;
    if secret.is_empty() || secret.len() > 4_096 || secret.contains(['\r', '\n']) {
        return Err(WitnessProcessErrorV1::Configuration);
    }
    let signer = Ed25519Signer::from_secret_material(&secret);
    if signer.key_id() != config.service.witness_key_id {
        return Err(WitnessProcessErrorV1::Configuration);
    }
    let proxy = NatsPublicWitnessStoreProxyClient::new(
        client.clone(),
        config.service.max_request_bytes,
        config.service.max_response_bytes,
        STORE_RESPONSE_GRANT_MILLIS,
    )
    .map_err(|_| WitnessProcessErrorV1::Configuration)?;
    let dispatcher = PublicWitnessDispatcher::new(config.service, signer, proxy)
        .await
        .map_err(|_| WitnessProcessErrorV1::Startup)?;
    let _runner = PublicWitnessServiceRunner::start(client, dispatcher)
        .await
        .map_err(|_| WitnessProcessErrorV1::Startup)?;
    std::future::pending::<()>().await;
    Ok(())
}

pub async fn run_store_proxy_process(
    config: StoreProxyProcessConfigV1,
) -> Result<(), WitnessProcessErrorV1> {
    config
        .validate()
        .map_err(|_| WitnessProcessErrorV1::Configuration)?;
    let raw_client = connect_exact_role(RoleTransportConfigV1 {
        nats_url: &config.service.nats_url,
        credentials_path: &config.service.nats_credentials_path,
        invocation_token: &config.service.credential_invocation_token,
        tls_ca_path: &config.service.tls_ca_path,
        tls_server_name: &config.service.tls_server_name,
        role: "witness-store",
        subscription_capacity: config.service.subscription_capacity,
        client_capacity: config.service.client_capacity,
        read_buffer_capacity: config.service.read_buffer_capacity,
        deadline_millis: STORE_RESPONSE_GRANT_MILLIS,
    })
    .await
    .map_err(|_| WitnessProcessErrorV1::Authentication)?;
    let store = NatsWitnessStore::open(
        async_nats::jetstream::new(raw_client),
        config.ready.clone(),
        &config.reported_server_version,
        &config.resolved_server_image_index_digest,
    )
    .await
    .map_err(|_| WitnessProcessErrorV1::Startup)?;
    let service = StoreProxyService::new(config.service.clone(), config.ready.clone(), store)
        .map_err(|_| WitnessProcessErrorV1::Startup)?;
    let connection = StoreRoleConnectionV1::connect(&config.service, &config.ready)
        .await
        .map_err(|_| WitnessProcessErrorV1::Authentication)?;
    let _runner = StoreProxyServiceRunner::start(connection, service)
        .await
        .map_err(|_| WitnessProcessErrorV1::Startup)?;
    std::future::pending::<()>().await;
    Ok(())
}

pub struct RuntimeWitnessClient {
    client: async_nats::Client,
    connection_client_id: u64,
    #[cfg(test)]
    authenticated_user: String,
    config: RuntimeWitnessClientConfigV1,
}

impl RuntimeWitnessClient {
    pub async fn connect(
        config: RuntimeWitnessClientConfigV1,
    ) -> Result<Self, RuntimeWitnessClientErrorV1> {
        config
            .validate()
            .map_err(|_| RuntimeWitnessClientErrorV1::Configuration)?;
        let raw = tokio::fs::read(&config.nats_credentials_path)
            .await
            .map_err(|_| RuntimeWitnessClientErrorV1::Configuration)?;
        if raw.is_empty() || raw.len() > 4_096 {
            return Err(RuntimeWitnessClientErrorV1::Configuration);
        }
        let credentials: RuntimeRoleCredentialFileV1 =
            serde_json::from_slice(&raw).map_err(|_| RuntimeWitnessClientErrorV1::Configuration)?;
        if serde_json::to_vec(&credentials).ok().as_deref() != Some(raw.as_slice())
            || credentials.schema_version != PROTOCOL_SCHEMA_VERSION
            || credentials.role != "runtime"
            || credentials.invocation_token != config.credential_invocation_token
            || credentials.username.is_empty()
            || credentials.password.is_empty()
            || credentials.username.len() > MAX_PROTOCOL_STRING_BYTES
            || credentials.password.len() > MAX_PROTOCOL_STRING_BYTES
        {
            return Err(RuntimeWitnessClientErrorV1::Configuration);
        }
        #[cfg(test)]
        let authenticated_user = credentials.username.clone();
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
        .map_err(|_| RuntimeWitnessClientErrorV1::Authentication)?
        .map_err(|_| RuntimeWitnessClientErrorV1::Authentication)?;
        timeout(
            Duration::from_millis(config.request_deadline_millis),
            client.flush(),
        )
        .await
        .map_err(|_| RuntimeWitnessClientErrorV1::Authentication)?
        .map_err(|_| RuntimeWitnessClientErrorV1::Authentication)?;
        let connection_client_id = client.server_info().client_id;
        Ok(Self {
            client,
            connection_client_id,
            #[cfg(test)]
            authenticated_user,
            config,
        })
    }

    pub fn connection_client_id(&self) -> u64 {
        self.connection_client_id
    }

    #[cfg(test)]
    pub(crate) async fn read_head_with_request_start_observation(
        &self,
        request: WitnessServiceRequestV1,
        origin: &Instant,
        request_started_at_micros: &AtomicU64,
    ) -> Result<WitnessReadAttestationV1, RuntimeWitnessClientErrorV1> {
        match self
            .request_observed(&request, Some((origin, request_started_at_micros)))
            .await?
        {
            WitnessServiceResponseV1::Read(value) => Ok(value),
            _ => Err(RuntimeWitnessClientErrorV1::InvalidResponse),
        }
    }

    #[cfg(test)]
    pub(crate) fn authenticated_user(&self) -> &str {
        &self.authenticated_user
    }

    async fn request(
        &self,
        request: &WitnessServiceRequestV1,
    ) -> Result<WitnessServiceResponseV1, RuntimeWitnessClientErrorV1> {
        self.request_observed(request, None).await
    }

    async fn request_observed(
        &self,
        request: &WitnessServiceRequestV1,
        #[cfg(test)] request_start_observation: Option<(&Instant, &AtomicU64)>,
        #[cfg(not(test))] _request_start_observation: Option<()>,
    ) -> Result<WitnessServiceResponseV1, RuntimeWitnessClientErrorV1> {
        let bytes = request
            .canonical_bytes()
            .map_err(|_| RuntimeWitnessClientErrorV1::RequestBounds)?;
        if bytes.len() > self.config.max_request_bytes {
            return Err(RuntimeWitnessClientErrorV1::RequestBounds);
        }
        #[cfg(test)]
        if let Some((origin, request_started_at_micros)) = request_start_observation {
            let observed = u64::try_from(origin.elapsed().as_micros())
                .map_err(|_| RuntimeWitnessClientErrorV1::Unavailable)?;
            request_started_at_micros.store(observed, Ordering::SeqCst);
        }
        let message = self
            .request_transport(
                PublicWitnessServiceConfigV1::subject_for(request.operation),
                bytes,
                Duration::from_millis(self.config.request_deadline_millis),
            )
            .await
            .map_err(map_request_error_kind)?;
        if message.payload.len() > self.config.max_response_bytes {
            return Err(RuntimeWitnessClientErrorV1::ResponseBounds);
        }
        let response =
            WitnessServiceResponseV1::decode_for_client_request(&message.payload, request)
                .map_err(|_| RuntimeWitnessClientErrorV1::InvalidResponse)?;
        if let WitnessServiceResponseV1::Failure(failure) = response {
            return Err(RuntimeWitnessClientErrorV1::Application(Box::new(failure)));
        }
        Ok(response)
    }

    async fn request_transport(
        &self,
        subject: &str,
        payload: Vec<u8>,
        deadline: Duration,
    ) -> Result<async_nats::Message, async_nats::RequestErrorKind> {
        let request = async_nats::Request::new()
            .payload(payload.into())
            .timeout(Some(deadline));
        timeout(
            deadline,
            self.client.send_request(subject.to_owned(), request),
        )
        .await
        .map_err(|_| async_nats::RequestErrorKind::TimedOut)?
        .map_err(|error| error.kind())
    }

    #[cfg(test)]
    pub(crate) async fn observe_transport_message_for_test(
        &self,
        subject: &str,
        payload: Vec<u8>,
        deadline: Duration,
    ) -> Result<async_nats::Message, (RuntimeRequestObservationV1, RuntimeWitnessClientErrorV1)>
    {
        match self.request_transport(subject, payload, deadline).await {
            Ok(message) => Ok(message),
            Err(kind) => Err((kind.into(), map_request_error_kind(kind))),
        }
    }

    #[cfg(test)]
    pub(crate) async fn observe_transport_for_test(
        &self,
        subject: &str,
        payload: Vec<u8>,
        deadline: Duration,
    ) -> Result<
        RuntimeRequestObservationV1,
        (RuntimeRequestObservationV1, RuntimeWitnessClientErrorV1),
    > {
        self.observe_transport_message_for_test(subject, payload, deadline)
            .await
            .map(|_| RuntimeRequestObservationV1::Response)
    }

    #[cfg(test)]
    pub(crate) async fn observe_response_bytes_for_test(
        &self,
        request: &WitnessServiceRequestV1,
    ) -> Result<(WitnessServiceResponseV1, Vec<u8>), RuntimeWitnessClientErrorV1> {
        let bytes = request
            .canonical_bytes()
            .map_err(|_| RuntimeWitnessClientErrorV1::RequestBounds)?;
        if bytes.len() > self.config.max_request_bytes {
            return Err(RuntimeWitnessClientErrorV1::RequestBounds);
        }
        let message = self
            .request_transport(
                PublicWitnessServiceConfigV1::subject_for(request.operation),
                bytes,
                Duration::from_millis(self.config.request_deadline_millis),
            )
            .await
            .map_err(map_request_error_kind)?;
        if message.payload.len() > self.config.max_response_bytes {
            return Err(RuntimeWitnessClientErrorV1::ResponseBounds);
        }
        let response_bytes = message.payload.to_vec();
        let response =
            WitnessServiceResponseV1::decode_for_client_request(&response_bytes, request)
                .map_err(|_| RuntimeWitnessClientErrorV1::InvalidResponse)?;
        if let WitnessServiceResponseV1::Failure(failure) = response {
            return Err(RuntimeWitnessClientErrorV1::Application(Box::new(failure)));
        }
        Ok((response, response_bytes))
    }

    #[cfg(test)]
    pub(crate) async fn drain_for_test(&self) -> Result<(), RuntimeWitnessClientErrorV1> {
        self.client
            .drain()
            .await
            .map_err(|_| RuntimeWitnessClientErrorV1::OutcomeUnknown)
    }
}

#[async_trait]
impl GovernanceDurabilityWitness for RuntimeWitnessClient {
    type Error = RuntimeWitnessClientErrorV1;

    async fn issue_session_fence(
        &self,
        request: WitnessServiceRequestV1,
    ) -> Result<WitnessSessionStateFenceV1, Self::Error> {
        match self.request(&request).await? {
            WitnessServiceResponseV1::Fence(value) => Ok(value),
            _ => Err(Self::Error::InvalidResponse),
        }
    }
    async fn establish_session(
        &self,
        request: WitnessServiceRequestV1,
    ) -> Result<WitnessSessionAttestationV1, Self::Error> {
        match self.request(&request).await? {
            WitnessServiceResponseV1::Establish(value) => Ok(value),
            _ => Err(Self::Error::InvalidResponse),
        }
    }
    async fn discover_stream(
        &self,
        request: WitnessServiceRequestV1,
    ) -> Result<WitnessDiscoveryAttestationV1, Self::Error> {
        match self.request(&request).await? {
            WitnessServiceResponseV1::Discover(value) => Ok(value),
            _ => Err(Self::Error::InvalidResponse),
        }
    }
    async fn prepare_successor(
        &self,
        request: WitnessServiceRequestV1,
    ) -> Result<WitnessOutcomeAttestationV1, Self::Error> {
        match self.request(&request).await? {
            WitnessServiceResponseV1::Outcome(value) => Ok(value),
            _ => Err(Self::Error::InvalidResponse),
        }
    }
    async fn commit_prepared(
        &self,
        request: WitnessServiceRequestV1,
    ) -> Result<WitnessOutcomeAttestationV1, Self::Error> {
        match self.request(&request).await? {
            WitnessServiceResponseV1::Outcome(value) => Ok(value),
            _ => Err(Self::Error::InvalidResponse),
        }
    }
    async fn abort_prepared(
        &self,
        request: WitnessServiceRequestV1,
    ) -> Result<WitnessOutcomeAttestationV1, Self::Error> {
        match self.request(&request).await? {
            WitnessServiceResponseV1::Outcome(value) => Ok(value),
            _ => Err(Self::Error::InvalidResponse),
        }
    }
    async fn read_prepared_for_stream(
        &self,
        request: WitnessServiceRequestV1,
    ) -> Result<WitnessReadAttestationV1, Self::Error> {
        match self.request(&request).await? {
            WitnessServiceResponseV1::Read(value) => Ok(value),
            _ => Err(Self::Error::InvalidResponse),
        }
    }
    async fn read_head(
        &self,
        request: WitnessServiceRequestV1,
    ) -> Result<WitnessReadAttestationV1, Self::Error> {
        match self.request(&request).await? {
            WitnessServiceResponseV1::Read(value) => Ok(value),
            _ => Err(Self::Error::InvalidResponse),
        }
    }
    async fn fetch_payload(
        &self,
        request: WitnessServiceRequestV1,
    ) -> Result<WitnessReadAttestationV1, Self::Error> {
        match self.request(&request).await? {
            WitnessServiceResponseV1::Read(value) => Ok(value),
            _ => Err(Self::Error::InvalidResponse),
        }
    }
}

#[cfg(test)]
mod request_error_mapping_tests {
    use super::*;

    #[test]
    fn request_error_mapping_is_closed_and_truthful() {
        use async_nats::RequestErrorKind::{InvalidSubject, NoResponders, Other, TimedOut};

        assert!(matches!(
            map_request_error_kind(TimedOut),
            RuntimeWitnessClientErrorV1::OutcomeUnknown
        ));
        assert!(matches!(
            map_request_error_kind(Other),
            RuntimeWitnessClientErrorV1::OutcomeUnknown
        ));
        assert!(matches!(
            map_request_error_kind(NoResponders),
            RuntimeWitnessClientErrorV1::Unavailable
        ));
        assert!(matches!(
            map_request_error_kind(InvalidSubject),
            RuntimeWitnessClientErrorV1::Configuration
        ));
    }
}
