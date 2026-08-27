use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use swarm_governance::persistence_protocol::{
    GovernanceDurabilityWitness, MAX_PROTOCOL_STRING_BYTES, PROTOCOL_SCHEMA_VERSION,
    WitnessDiscoveryAttestationV1, WitnessOutcomeAttestationV1, WitnessReadAttestationV1,
    WitnessSessionAttestationV1, WitnessSessionStateFenceV1,
};
use swarm_governance::witness_service::{
    WitnessServiceFailureAttestationV1, WitnessServiceRequestV1, WitnessServiceResponseV1,
};
use tokio::time::{Duration, timeout};

use crate::{PublicWitnessServiceConfigV1, RuntimeWitnessClientConfigV1};

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
    pub(crate) fn authenticated_user(&self) -> &str {
        &self.authenticated_user
    }

    async fn request(
        &self,
        request: &WitnessServiceRequestV1,
    ) -> Result<WitnessServiceResponseV1, RuntimeWitnessClientErrorV1> {
        let bytes = request
            .canonical_bytes()
            .map_err(|_| RuntimeWitnessClientErrorV1::RequestBounds)?;
        if bytes.len() > self.config.max_request_bytes {
            return Err(RuntimeWitnessClientErrorV1::RequestBounds);
        }
        let message = timeout(
            Duration::from_millis(self.config.request_deadline_millis),
            self.client.request(
                PublicWitnessServiceConfigV1::subject_for(request.operation),
                bytes.into(),
            ),
        )
        .await
        .map_err(|_| RuntimeWitnessClientErrorV1::OutcomeUnknown)?
        .map_err(|error| match error.kind() {
            async_nats::RequestErrorKind::TimedOut => RuntimeWitnessClientErrorV1::OutcomeUnknown,
            _ => RuntimeWitnessClientErrorV1::Unavailable,
        })?;
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
