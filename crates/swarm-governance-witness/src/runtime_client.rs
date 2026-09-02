use async_trait::async_trait;
use futures_util::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
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
use tokio::time::{Duration, Instant as TokioInstant, timeout, timeout_at};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use swarm_crypto::Ed25519Signer;

use crate::raw_config::relay_topology_token_is_closed;
use crate::secure_file::{StableFilePolicyV1, read_stable_file, read_stable_tls_client_config};
use crate::service_config::{PUBLIC_RESPONSE_GRANT_MILLIS, STORE_RESPONSE_GRANT_MILLIS};
use crate::{
    NatsPublicWitnessStoreProxyClient, NatsWitnessStore, PublicWitnessDispatcher,
    PublicWitnessProcessConfigV1, PublicWitnessServiceConfigV1, PublicWitnessServiceRunner,
    RuntimeWitnessClientConfigV1, StoreProxyProcessConfigV1, StoreProxyService,
    StoreProxyServiceRunner, StoreRoleConnectionV1,
};

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct RuntimeRoleCredentialFileV1 {
    schema_version: u32,
    role: String,
    username: String,
    password: String,
    invocation_token: String,
}

const MAX_ROLE_CREDENTIAL_BYTES: usize = 4_096;
const MAX_SIGNING_KEY_BYTES: usize = 4_096;
const MAX_CA_BYTES: usize = 1_048_576;
const MAX_PROCESS_CONFIG_BYTES: usize = 2_097_152;

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
    #[error("runtime witness request has unknown outcome")]
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
    #[error("service capability exited abnormally")]
    AbnormalExit,
    #[error("service shutdown did not complete")]
    Shutdown,
}

fn load_canonical_process_config<T>(path: &Path) -> Result<T, WitnessProcessErrorV1>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let bytes = read_stable_file(path, MAX_PROCESS_CONFIG_BYTES, StableFilePolicyV1::Private)
        .map_err(|_| WitnessProcessErrorV1::Configuration)?;
    let value = serde_json::from_slice(&bytes).map_err(|_| WitnessProcessErrorV1::Configuration)?;
    let canonical = Zeroizing::new(
        serde_json::to_vec(&value).map_err(|_| WitnessProcessErrorV1::Configuration)?,
    );
    if canonical.as_slice() != bytes.as_slice() {
        return Err(WitnessProcessErrorV1::Configuration);
    }
    Ok(value)
}

pub fn load_public_witness_process_config(
    path: impl AsRef<Path>,
) -> Result<PublicWitnessProcessConfigV1, WitnessProcessErrorV1> {
    load_canonical_process_config(path.as_ref())
}

pub fn load_store_proxy_process_config(
    path: impl AsRef<Path>,
) -> Result<StoreProxyProcessConfigV1, WitnessProcessErrorV1> {
    load_canonical_process_config(path.as_ref())
}

fn map_request_error_kind(kind: async_nats::RequestErrorKind) -> RuntimeWitnessClientErrorV1 {
    match kind {
        async_nats::RequestErrorKind::TimedOut => RuntimeWitnessClientErrorV1::OutcomeUnknown,
        async_nats::RequestErrorKind::Other => RuntimeWitnessClientErrorV1::OutcomeUnknown,
        async_nats::RequestErrorKind::NoResponders => RuntimeWitnessClientErrorV1::Unavailable,
        async_nats::RequestErrorKind::InvalidSubject => RuntimeWitnessClientErrorV1::Configuration,
    }
}

pub(crate) fn copy_zeroizing_utf8_secret(
    bytes: &Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<String>, WitnessProcessErrorV1> {
    Ok(Zeroizing::new(
        std::str::from_utf8(bytes.as_slice())
            .map_err(|_| WitnessProcessErrorV1::Configuration)?
            .to_owned(),
    ))
}

pub(crate) fn service_event_is_terminal(event: &async_nats::Event) -> bool {
    !matches!(
        event,
        async_nats::Event::Connected | async_nats::Event::Disconnected
    )
}

async fn wait_for_connection_failure(mut events: tokio::sync::mpsc::Receiver<async_nats::Event>) {
    while let Some(event) = events.recv().await {
        if service_event_is_terminal(&event) {
            return;
        }
    }
}

/// Waits for an owned capability task without transferring ownership of its
/// join handle. Cancelling this future therefore cannot detach the task.
pub(crate) async fn wait_for_owned_task_failure(tasks: &mut Vec<tokio::task::JoinHandle<()>>) {
    debug_assert!(!tasks.is_empty());
    let (_result, completed_index, _remaining_borrows) =
        futures_util::future::select_all(tasks.iter_mut()).await;
    // The selected handle has already produced Ready; remove it without
    // polling it a second time. All other handles stayed in `tasks` if this
    // wait was cancelled.
    drop(tasks.swap_remove(completed_index));
}

/// Cancels and joins every owned task. Only cancellation requested by this
/// invocation is an expected exit. A task that had already finished, races to
/// a normal return, or panics remains an abnormal capability exit.
pub(crate) async fn cancel_and_join_owned_tasks(
    tasks: &mut Vec<tokio::task::JoinHandle<()>>,
) -> Result<(), ()> {
    let mut cancellation_flags = Vec::with_capacity(tasks.len());
    for task in tasks.iter() {
        let cancellation_requested_here = !task.is_finished();
        if cancellation_requested_here {
            task.abort();
        }
        cancellation_flags.push(cancellation_requested_here);
    }

    let mut abnormal = false;
    while !tasks.is_empty() {
        let (result, completed_index, _remaining_borrows) =
            futures_util::future::select_all(tasks.iter_mut()).await;
        let expected_cancellation = cancellation_flags.swap_remove(completed_index);
        drop(tasks.swap_remove(completed_index));
        match result {
            Err(error) if expected_cancellation && error.is_cancelled() => {}
            Ok(()) | Err(_) => abnormal = true,
        }
    }
    if abnormal { Err(()) } else { Ok(()) }
}

#[cfg(test)]
mod service_lifecycle_unit_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn must<T, E: std::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error:?}"),
        }
    }

    #[test]
    fn terminal_events_include_closed_reconnect_exhaustion_and_slow_consumer() {
        assert!(!service_event_is_terminal(&async_nats::Event::Connected));
        assert!(!service_event_is_terminal(&async_nats::Event::Disconnected));
        assert!(service_event_is_terminal(&async_nats::Event::Closed));
        assert!(service_event_is_terminal(&async_nats::Event::SlowConsumer(
            7
        )));
        assert!(service_event_is_terminal(&async_nats::Event::ClientError(
            async_nats::ClientError::MaxReconnects,
        )));
    }

    #[test]
    fn signing_secret_utf8_conversion_never_creates_an_unwrapped_byte_copy() {
        let valid = Zeroizing::new(b"signing-secret".to_vec());
        assert_eq!(
            must(copy_zeroizing_utf8_secret(&valid), "valid UTF-8 secret").as_str(),
            "signing-secret"
        );
        let invalid = Zeroizing::new(vec![0xff, 0xfe]);
        assert!(matches!(
            copy_zeroizing_utf8_secret(&invalid),
            Err(WitnessProcessErrorV1::Configuration)
        ));
    }

    #[tokio::test]
    async fn cancelling_failure_wait_retains_and_stops_every_owned_task() {
        let completed = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..3 {
            let completed = completed.clone();
            tasks.push(tokio::spawn(async move {
                std::future::pending::<()>().await;
                completed.fetch_add(1, Ordering::SeqCst);
            }));
        }
        assert!(
            tokio::time::timeout(
                Duration::from_millis(10),
                wait_for_owned_task_failure(&mut tasks),
            )
            .await
            .is_err()
        );
        assert_eq!(tasks.len(), 3, "cancellation must retain every join handle");
        assert!(cancel_and_join_owned_tasks(&mut tasks).await.is_ok());
        assert!(tasks.is_empty());
        assert_eq!(completed.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn stop_accepts_only_cancellation_requested_by_that_stop() {
        let mut pending = vec![tokio::spawn(std::future::pending::<()>())];
        assert!(cancel_and_join_owned_tasks(&mut pending).await.is_ok());

        let mut returned = vec![tokio::spawn(async {})];
        while !returned[0].is_finished() {
            tokio::task::yield_now().await;
        }
        assert!(cancel_and_join_owned_tasks(&mut returned).await.is_err());

        let mut panicked = vec![tokio::spawn(async { panic!("capability panic control") })];
        while !panicked[0].is_finished() {
            tokio::task::yield_now().await;
        }
        assert!(cancel_and_join_owned_tasks(&mut panicked).await.is_err());
    }

    #[tokio::test]
    async fn repeated_signals_do_not_duplicate_or_bypass_held_stop() {
        let stop_starts = Arc::new(AtomicUsize::new(0));
        let stop_completed = Arc::new(AtomicUsize::new(0));
        let signals_observed = Arc::new(AtomicUsize::new(0));
        let signal_observed_notify = Arc::new(tokio::sync::Notify::new());
        let (release_sender, release_receiver) = tokio::sync::oneshot::channel::<()>();
        let (started_sender, started_receiver) = tokio::sync::oneshot::channel::<()>();
        let (signal_sender, signal_receiver) = tokio::sync::mpsc::unbounded_channel();
        let _signal_sender_guard = signal_sender.clone();
        let starts = stop_starts.clone();
        let completed = stop_completed.clone();
        let stop = async move {
            starts.fetch_add(1, Ordering::SeqCst);
            must(started_sender.send(()), "announce first stop poll");
            must(release_receiver.await, "release held stop");
            completed.fetch_add(1, Ordering::SeqCst);
            7_u8
        };
        let observed = signals_observed.clone();
        let observed_notify = signal_observed_notify.clone();
        let repeated = futures_util::stream::unfold(signal_receiver, |mut receiver| async move {
            receiver.recv().await.map(|event| (event, receiver))
        })
        .inspect(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            observed_notify.notify_waiters();
        });
        let mut repeated = Box::pin(repeated);
        let emit_signals = tokio::spawn(async move {
            must(started_receiver.await, "stop is polled first");
            must(
                signal_sender.send(Ok::<(), WitnessProcessErrorV1>(())),
                "first repeated signal",
            );
            must(
                signal_sender.send(Ok::<(), WitnessProcessErrorV1>(())),
                "second repeated signal",
            );
        });
        let release_starts = stop_starts.clone();
        let release_completed = stop_completed.clone();
        let release = tokio::spawn(async move {
            loop {
                let notified = signal_observed_notify.notified();
                if signals_observed.load(Ordering::SeqCst) == 2 {
                    break;
                }
                notified.await;
            }
            assert_eq!(release_starts.load(Ordering::SeqCst), 1);
            assert_eq!(release_completed.load(Ordering::SeqCst), 0);
            must(release_sender.send(()), "stop still awaits release");
        });

        let (result, repeated_count) = must(
            complete_single_stop_while_observing_signals(stop, repeated.as_mut()).await,
            "signal observation remains available during stop",
        );
        must(release.await, "release task");
        must(emit_signals.await, "signal emitter");
        assert_eq!(result, 7);
        assert_eq!(repeated_count, 2);
        assert_eq!(stop_starts.load(Ordering::SeqCst), 1);
        assert_eq!(stop_completed.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn signal_observer_failure_still_completes_the_owned_stop() {
        let completed = Arc::new(AtomicUsize::new(0));
        let completion = completed.clone();
        let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
        let (release_sender, release_receiver) = tokio::sync::oneshot::channel();
        let stop = async move {
            must(started_sender.send(()), "announce stop poll");
            must(release_receiver.await, "release stop");
            completion.fetch_add(1, Ordering::SeqCst);
        };
        let mut signals = Box::pin(futures_util::stream::iter([Err(
            WitnessProcessErrorV1::Startup,
        )]));
        let release = tokio::spawn(async move {
            must(started_receiver.await, "stop started");
            must(release_sender.send(()), "stop remains owned");
        });

        assert!(matches!(
            complete_single_stop_while_observing_signals(stop, signals.as_mut()).await,
            Err(WitnessProcessErrorV1::Startup)
        ));
        must(release.await, "release task");
        assert_eq!(completed.load(Ordering::SeqCst), 1);
    }
}

#[cfg(unix)]
struct ShutdownSignalSetV1 {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl ShutdownSignalSetV1 {
    fn new() -> Result<Self, WitnessProcessErrorV1> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())
                .map_err(|_| WitnessProcessErrorV1::Startup)?,
            terminate: signal(SignalKind::terminate())
                .map_err(|_| WitnessProcessErrorV1::Startup)?,
        })
    }

    async fn recv(&mut self) -> Result<(), WitnessProcessErrorV1> {
        tokio::select! {
            value = self.interrupt.recv() => value.ok_or(WitnessProcessErrorV1::Startup),
            value = self.terminate.recv() => value.ok_or(WitnessProcessErrorV1::Startup),
        }
    }
}

#[cfg(not(unix))]
struct ShutdownSignalSetV1;

#[cfg(not(unix))]
impl ShutdownSignalSetV1 {
    fn new() -> Result<Self, WitnessProcessErrorV1> {
        Ok(Self)
    }

    async fn recv(&mut self) -> Result<(), WitnessProcessErrorV1> {
        tokio::signal::ctrl_c()
            .await
            .map_err(|_| WitnessProcessErrorV1::Startup)
    }
}

fn shutdown_signal_stream(
    signals: ShutdownSignalSetV1,
) -> impl Stream<Item = Result<(), WitnessProcessErrorV1>> {
    futures_util::stream::unfold(signals, |mut signals| async move {
        let event = signals.recv().await;
        Some((event, signals))
    })
}

async fn complete_single_stop_while_observing_signals<F, S>(
    stop: F,
    mut signals: Pin<&mut S>,
) -> Result<(F::Output, usize), WitnessProcessErrorV1>
where
    F: Future,
    S: Stream<Item = Result<(), WitnessProcessErrorV1>>,
{
    tokio::pin!(stop);
    let mut repeated_signals = 0_usize;
    let mut observe_signals = true;
    let mut signal_failure = None;
    loop {
        tokio::select! {
            result = &mut stop => {
                return match signal_failure {
                    Some(error) => Err(error),
                    None => Ok((result, repeated_signals)),
                };
            }
            signal = signals.next(), if observe_signals => {
                match signal {
                    Some(Ok(())) => {
                        if let Some(next) = repeated_signals.checked_add(1) {
                            repeated_signals = next;
                        } else {
                            signal_failure = Some(WitnessProcessErrorV1::Shutdown);
                            observe_signals = false;
                        }
                    }
                    Some(Err(error)) => {
                        signal_failure = Some(error);
                        observe_signals = false;
                    }
                    None => {
                        signal_failure = Some(WitnessProcessErrorV1::Startup);
                        observe_signals = false;
                    }
                }
            }
        }
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
impl RuntimeRequestObservationV1 {
    pub(crate) const fn is_replay_response(self) -> bool {
        matches!(self, Self::Response)
    }
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

pub(crate) struct RoleTransportConfigV1<'a> {
    pub(crate) nats_url: &'a str,
    pub(crate) credentials_path: &'a str,
    pub(crate) invocation_token: &'a str,
    pub(crate) tls_ca_path: &'a str,
    pub(crate) tls_server_name: &'a str,
    pub(crate) role: &'static str,
    pub(crate) subscription_capacity: usize,
    pub(crate) client_capacity: usize,
    pub(crate) read_buffer_capacity: u16,
    pub(crate) deadline_millis: u64,
}

pub(crate) struct ConnectedRoleV1 {
    pub(crate) client: async_nats::Client,
    pub(crate) lifecycle_events: tokio::sync::mpsc::Receiver<async_nats::Event>,
}

fn tls_authority(url: &str) -> Option<&str> {
    let authority = url.strip_prefix("tls://")?;
    if authority.contains(['@', '/', '?']) {
        return None;
    }
    authority.rsplit_once(':').map(|(host, _)| host)
}

pub(crate) async fn connect_exact_role(
    config: RoleTransportConfigV1<'_>,
) -> Result<ConnectedRoleV1, RuntimeWitnessClientErrorV1> {
    if config.deadline_millis == 0 || tls_authority(config.nats_url) != Some(config.tls_server_name)
    {
        return Err(RuntimeWitnessClientErrorV1::Configuration);
    }
    let tls_client_config = read_stable_tls_client_config(config.tls_ca_path, MAX_CA_BYTES)
        .map_err(|_| RuntimeWitnessClientErrorV1::Configuration)?;
    let raw = read_stable_file(
        config.credentials_path,
        MAX_ROLE_CREDENTIAL_BYTES,
        StableFilePolicyV1::Private,
    )
    .map_err(|_| RuntimeWitnessClientErrorV1::Configuration)?;
    let credentials: RuntimeRoleCredentialFileV1 =
        serde_json::from_slice(&raw).map_err(|_| RuntimeWitnessClientErrorV1::Configuration)?;
    let canonical = Zeroizing::new(
        serde_json::to_vec(&credentials).map_err(|_| RuntimeWitnessClientErrorV1::Configuration)?,
    );
    if canonical.as_slice() != raw.as_slice()
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
    let username = Zeroizing::new(credentials.username.clone());
    let password = Zeroizing::new(credentials.password.clone());
    let (lifecycle_sender, lifecycle_events) = tokio::sync::mpsc::channel(1_024);
    let options = async_nats::ConnectOptions::with_user_and_password(
        username.to_string(),
        password.to_string(),
    )
    .require_tls(true)
    .tls_client_config(tls_client_config)
    .subscription_capacity(config.subscription_capacity)
    .client_capacity(config.client_capacity)
    .read_buffer_capacity(config.read_buffer_capacity)
    .connection_timeout(Duration::from_millis(config.deadline_millis))
    .request_timeout(Some(Duration::from_millis(config.deadline_millis)))
    .max_reconnects(Some(1))
    .event_callback(move |event| {
        let sender = lifecycle_sender.clone();
        async move {
            let _ = sender.send(event).await;
        }
    });
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
    Ok(ConnectedRoleV1 {
        client,
        lifecycle_events,
    })
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
    let connection = connect_exact_role(RoleTransportConfigV1 {
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
    let secret_bytes = read_stable_file(
        &config.service.witness_key_path,
        MAX_SIGNING_KEY_BYTES,
        StableFilePolicyV1::Private,
    )
    .map_err(|_| WitnessProcessErrorV1::Configuration)?;
    let secret = copy_zeroizing_utf8_secret(&secret_bytes)?;
    if secret.is_empty() || secret.len() > 4_096 || secret.contains(['\r', '\n']) {
        return Err(WitnessProcessErrorV1::Configuration);
    }
    let signer = Ed25519Signer::from_secret_material(secret.as_str());
    if signer.key_id() != config.service.witness_key_id {
        return Err(WitnessProcessErrorV1::Configuration);
    }
    let proxy = NatsPublicWitnessStoreProxyClient::new(
        connection.client.clone(),
        config.service.max_request_bytes,
        config.service.max_response_bytes,
        STORE_RESPONSE_GRANT_MILLIS,
    )
    .map_err(|_| WitnessProcessErrorV1::Configuration)?;
    let dispatcher = PublicWitnessDispatcher::new(config.service, signer, proxy)
        .await
        .map_err(|_| WitnessProcessErrorV1::Startup)?;
    let mut runner = PublicWitnessServiceRunner::start_supervised(
        connection.client,
        dispatcher,
        connection.lifecycle_events,
    )
    .await
    .map_err(|_| WitnessProcessErrorV1::Startup)?;
    let mut signals = Box::pin(shutdown_signal_stream(ShutdownSignalSetV1::new()?));
    let mut initial_signal_failure = false;
    let abnormal = tokio::select! {
        signal = signals.next() => {
            match signal {
                Some(Ok(())) => false,
                Some(Err(_)) | None => {
                    initial_signal_failure = true;
                    true
                }
            }
        }
        _ = runner.wait_for_failure() => true,
    };
    let (stop_result, _repeated_signals) = complete_single_stop_while_observing_signals(
        runner.stop_and_wait(Duration::from_millis(PUBLIC_RESPONSE_GRANT_MILLIS)),
        signals.as_mut(),
    )
    .await?;
    match stop_result {
        Ok(()) => {}
        Err(crate::PublicWitnessRunnerErrorV1::TaskExit) => {
            return Err(WitnessProcessErrorV1::AbnormalExit);
        }
        Err(_) => return Err(WitnessProcessErrorV1::Shutdown),
    }
    if initial_signal_failure {
        return Err(WitnessProcessErrorV1::Startup);
    }
    if abnormal {
        Err(WitnessProcessErrorV1::AbnormalExit)
    } else {
        Ok(())
    }
}

pub async fn run_store_proxy_process(
    config: StoreProxyProcessConfigV1,
) -> Result<(), WitnessProcessErrorV1> {
    config
        .validate()
        .map_err(|_| WitnessProcessErrorV1::Configuration)?;
    let raw_connection = connect_exact_role(RoleTransportConfigV1 {
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
    let raw_client = raw_connection.client;
    let raw_drain_client = raw_client.clone();
    let raw_failure = wait_for_connection_failure(raw_connection.lifecycle_events);
    tokio::pin!(raw_failure);
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
    let mut runner = StoreProxyServiceRunner::start(connection, service)
        .await
        .map_err(|_| WitnessProcessErrorV1::Startup)?;
    let mut signals = Box::pin(shutdown_signal_stream(ShutdownSignalSetV1::new()?));
    let mut initial_signal_failure = false;
    let abnormal = tokio::select! {
        signal = signals.next() => {
            match signal {
                Some(Ok(())) => false,
                Some(Err(_)) | None => {
                    initial_signal_failure = true;
                    true
                }
            }
        }
        _ = runner.wait_for_failure() => true,
        _ = &mut raw_failure => true,
    };
    let stop = timeout(Duration::from_millis(STORE_RESPONSE_GRANT_MILLIS), async {
        runner
            .stop_and_wait(Duration::from_millis(STORE_RESPONSE_GRANT_MILLIS))
            .await
            .map_err(|error| match error {
                crate::StoreProxyRunnerErrorV1::TaskExit => WitnessProcessErrorV1::AbnormalExit,
                _ => WitnessProcessErrorV1::Shutdown,
            })?;
        raw_drain_client
            .drain()
            .await
            .map_err(|_| WitnessProcessErrorV1::Shutdown)
    });
    let (stop_result, _repeated_signals) =
        complete_single_stop_while_observing_signals(stop, signals.as_mut()).await?;
    stop_result.map_err(|_| WitnessProcessErrorV1::Shutdown)??;
    if initial_signal_failure {
        return Err(WitnessProcessErrorV1::Startup);
    }
    if abnormal {
        Err(WitnessProcessErrorV1::AbnormalExit)
    } else {
        Ok(())
    }
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
        let tls_client_config = read_stable_tls_client_config(&config.tls_ca_path, MAX_CA_BYTES)
            .map_err(|_| RuntimeWitnessClientErrorV1::Configuration)?;
        let raw = read_stable_file(
            &config.nats_credentials_path,
            MAX_ROLE_CREDENTIAL_BYTES,
            StableFilePolicyV1::Private,
        )
        .map_err(|_| RuntimeWitnessClientErrorV1::Configuration)?;
        let credentials: RuntimeRoleCredentialFileV1 =
            serde_json::from_slice(&raw).map_err(|_| RuntimeWitnessClientErrorV1::Configuration)?;
        let canonical = Zeroizing::new(
            serde_json::to_vec(&credentials)
                .map_err(|_| RuntimeWitnessClientErrorV1::Configuration)?,
        );
        if canonical.as_slice() != raw.as_slice()
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
        let username = Zeroizing::new(credentials.username.clone());
        let password = Zeroizing::new(credentials.password.clone());
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
        let deadline =
            TokioInstant::now() + Duration::from_millis(self.config.request_deadline_millis);
        let bytes = request
            .canonical_bytes()
            .map_err(|_| RuntimeWitnessClientErrorV1::RequestBounds)?;
        if bytes.len() > self.config.max_request_bytes {
            return Err(RuntimeWitnessClientErrorV1::RequestBounds);
        }
        if TokioInstant::now() >= deadline {
            return Err(RuntimeWitnessClientErrorV1::OutcomeUnknown);
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
                deadline,
            )
            .await
            .map_err(map_request_error_kind)?;
        if message.payload.len() > self.config.max_response_bytes {
            return Err(RuntimeWitnessClientErrorV1::ResponseBounds);
        }
        if TokioInstant::now() >= deadline {
            return Err(RuntimeWitnessClientErrorV1::OutcomeUnknown);
        }
        let response =
            WitnessServiceResponseV1::decode_for_client_request(&message.payload, request)
                .map_err(|_| RuntimeWitnessClientErrorV1::InvalidResponse)?;
        if TokioInstant::now() >= deadline {
            return Err(RuntimeWitnessClientErrorV1::OutcomeUnknown);
        }
        if let WitnessServiceResponseV1::Failure(failure) = response {
            return Err(RuntimeWitnessClientErrorV1::Application(Box::new(failure)));
        }
        Ok(response)
    }

    async fn request_transport(
        &self,
        subject: &str,
        payload: Vec<u8>,
        deadline: TokioInstant,
    ) -> Result<async_nats::Message, async_nats::RequestErrorKind> {
        let remaining = deadline.saturating_duration_since(TokioInstant::now());
        if remaining.is_zero() {
            return Err(async_nats::RequestErrorKind::TimedOut);
        }
        let request = async_nats::Request::new()
            .payload(payload.into())
            .timeout(Some(remaining));
        timeout_at(
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
        match self
            .request_transport(subject, payload, TokioInstant::now() + deadline)
            .await
        {
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
        let deadline =
            TokioInstant::now() + Duration::from_millis(self.config.request_deadline_millis);
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
                deadline,
            )
            .await
            .map_err(map_request_error_kind)?;
        if message.payload.len() > self.config.max_response_bytes {
            return Err(RuntimeWitnessClientErrorV1::ResponseBounds);
        }
        if TokioInstant::now() >= deadline {
            return Err(RuntimeWitnessClientErrorV1::OutcomeUnknown);
        }
        let response_bytes = message.payload.to_vec();
        let response =
            WitnessServiceResponseV1::decode_for_client_request(&response_bytes, request)
                .map_err(|_| RuntimeWitnessClientErrorV1::InvalidResponse)?;
        if TokioInstant::now() >= deadline {
            return Err(RuntimeWitnessClientErrorV1::OutcomeUnknown);
        }
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
        assert_eq!(
            RuntimeWitnessClientErrorV1::OutcomeUnknown.to_string(),
            "runtime witness request has unknown outcome"
        );
    }
}
