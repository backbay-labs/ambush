use axum::Router;
use axum::body::Body;
use hyper::Request;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::sync::Arc;
use std::sync::OnceLock;
use swarm_core::config::TlsConfig;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::server::danger::ClientCertVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use tower::Service;
use x509_parser::parse_x509_certificate;

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("http server exited: {0}")]
    Http(#[source] io::Error),

    #[error("failed to load TLS server configuration: {0}")]
    TlsConfig(#[source] io::Error),

    #[error("failed to wait for shutdown signal: {0}")]
    ShutdownSignal(#[source] io::Error),

    #[error("failed to accept incoming connection: {0}")]
    Accept(#[source] io::Error),

    #[error("TLS connection task exited unexpectedly: {0}")]
    TaskJoin(#[from] tokio::task::JoinError),

    #[error("TLS connection failed: {0}")]
    Connection(#[source] io::Error),
}

#[derive(Debug, Clone)]
pub struct TlsClientIdentity(Arc<str>);

impl TlsClientIdentity {
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

pub async fn serve_with_listener<F>(
    listener: TcpListener,
    app: Router,
    tls: Option<TlsConfig>,
    shutdown: F,
) -> Result<(), ServeError>
where
    F: Future<Output = ()> + Send + 'static,
{
    if let Some(tls) = tls {
        serve_tls_with_listener(listener, app, tls, shutdown).await
    } else {
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await
            .map_err(ServeError::Http)
    }
}

async fn serve_tls_with_listener<F>(
    listener: TcpListener,
    app: Router,
    tls: TlsConfig,
    shutdown: F,
) -> Result<(), ServeError>
where
    F: Future<Output = ()> + Send + 'static,
{
    let acceptor = TlsAcceptor::from(Arc::new(
        load_server_config(&tls).map_err(ServeError::TlsConfig)?,
    ));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut shutdown_task = Some(tokio::spawn(async move {
        shutdown.await;
        let _ = shutdown_tx.send(true);
    }));
    let mut connection_tasks = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            changed = wait_for_shutdown_signal(shutdown_rx.clone()) => {
                changed?;
                break;
            }
            accepted = listener.accept() => {
                let (stream, peer_addr) = accepted.map_err(ServeError::Accept)?;
                let acceptor = acceptor.clone();
                let app = app.clone();
                let connection_shutdown = shutdown_rx.clone();
                connection_tasks.spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(stream) => stream,
                        Err(error) => {
                            tracing::warn!(
                                peer_addr = %peer_addr,
                                error = %error,
                                "rejected TLS connection"
                            );
                            return Ok(()) as Result<(), ServeError>;
                        }
                    };
                    let client_identity = extract_client_identity(tls_stream.get_ref().1);
                    tracing::debug!(
                        peer_addr = %peer_addr,
                        tls_client_identity = client_identity.as_deref().unwrap_or("none"),
                        "accepted TLS connection"
                    );

                    let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                        let mut router = app.clone();
                        let client_identity = client_identity.clone();
                        async move {
                            let (parts, body) = request.into_parts();
                            let mut request = Request::from_parts(parts, Body::new(body));
                            if let Some(identity) = client_identity {
                                request
                                    .extensions_mut()
                                    .insert(TlsClientIdentity(Arc::from(identity)));
                            }
                            let response = router
                                .call(request)
                                .await
                                .unwrap_or_else(|err| match err {});
                            Ok::<_, Infallible>(response)
                        }
                    });

                    let connection = http1::Builder::new()
                        .keep_alive(false)
                        .serve_connection(TokioIo::new(tls_stream), service);
                    tokio::pin!(connection);

                    tokio::select! {
                        result = &mut connection => {
                            result
                                .map_err(io::Error::other)
                                .map_err(ServeError::Connection)?;
                        }
                        changed = wait_for_shutdown_signal(connection_shutdown) => {
                            changed?;
                            connection.as_mut().graceful_shutdown();
                            connection
                                .await
                                .map_err(io::Error::other)
                                .map_err(ServeError::Connection)?;
                        }
                    }
                    Ok(())
                });
            }
        }
    }

    while let Some(result) = connection_tasks.join_next().await {
        result.map_err(ServeError::TaskJoin)??;
    }
    if let Some(task) = shutdown_task.take() {
        task.abort();
    }
    Ok(())
}

fn ensure_crypto_provider_installed() {
    static CRYPTO_PROVIDER: OnceLock<()> = OnceLock::new();
    CRYPTO_PROVIDER.get_or_init(|| {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    });
}

async fn wait_for_shutdown_signal(
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), ServeError> {
    loop {
        shutdown_rx
            .changed()
            .await
            .map_err(io::Error::other)
            .map_err(ServeError::ShutdownSignal)?;
        if *shutdown_rx.borrow() {
            return Ok(());
        }
    }
}

fn load_server_config(tls: &TlsConfig) -> io::Result<ServerConfig> {
    ensure_crypto_provider_installed();
    let certs = load_certificates(&tls.cert_path)?;
    let key = load_private_key(&tls.key_path)?;
    let mut server = if let Some(client_ca_cert) = tls.client_ca_cert.as_deref() {
        let verifier = client_verifier(client_ca_cert)?;
        ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(io::Error::other)?
    } else {
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(io::Error::other)?
    };
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(server)
}

fn load_certificates(path: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)
}

fn load_private_key(path: &str) -> io::Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing private key"))
}

fn client_verifier(path: &str) -> io::Result<Arc<dyn ClientCertVerifier>> {
    let certs = load_certificates(path)?;
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots.add(cert).map_err(io::Error::other)?;
    }
    WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(io::Error::other)
}

fn extract_client_identity(connection: &tokio_rustls::rustls::ServerConnection) -> Option<String> {
    let cert = connection.peer_certificates()?.first()?;
    client_identity_from_certificate(cert).or_else(|| Some("unknown".to_string()))
}

fn client_identity_from_certificate(cert: &CertificateDer<'_>) -> Option<String> {
    let (_, certificate) = parse_x509_certificate(cert.as_ref()).ok()?;
    certificate
        .subject()
        .iter_common_name()
        .next()
        .and_then(|common_name| common_name.as_str().ok())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::{ServeError, serve_with_listener};
    use axum::Router;
    use axum::routing::get;
    use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
    use reqwest::{Certificate, Client, Identity};
    use std::net::TcpListener as StdTcpListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use swarm_core::config::TlsConfig;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    static TLS_TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

    #[tokio::test]
    async fn tls_server_serves_https_requests() {
        let materials = TlsTestMaterials::server_only("localhost");
        let (listener, address) = bind_listener();
        let app = Router::new().route("/readyz", get(|| async { "ok" }));
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(serve_with_listener(
            listener,
            app,
            Some(materials.server_tls_config()),
            async move {
                let _ = shutdown_rx.await;
            },
        ));

        let response = tls_client(&materials.ca_cert_pem, None)
            .get(format!("https://{address}/readyz"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "ok");

        let _ = shutdown_tx.send(());
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn tls_server_requires_client_cert_when_configured() {
        let materials = TlsTestMaterials::mutual_tls("localhost", "swarm-client");
        let (listener, address) = bind_listener();
        let app = Router::new().route("/readyz", get(|| async { "ok" }));
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(serve_with_listener(
            listener,
            app,
            Some(materials.mtls_server_config()),
            async move {
                let _ = shutdown_rx.await;
            },
        ));

        let without_identity = tls_client(&materials.ca_cert_pem, None)
            .get(format!("https://{address}/readyz"))
            .send()
            .await;
        assert!(without_identity.is_err());

        let identity = Identity::from_pem(
            format!(
                "{}\n{}",
                materials.client_cert_pem.as_deref().unwrap(),
                materials.client_key_pem.as_deref().unwrap()
            )
            .as_bytes(),
        )
        .unwrap();
        let with_identity = tls_client(&materials.ca_cert_pem, Some(identity))
            .get(format!("https://{address}/readyz"))
            .send()
            .await
            .unwrap();
        assert_eq!(with_identity.status(), reqwest::StatusCode::OK);

        let _ = shutdown_tx.send(());
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn tls_server_reports_typed_config_error_for_missing_cert() {
        let dir = unique_temp_dir();
        let missing_cert = dir.join("missing-cert.pem");
        let missing_key = dir.join("missing-key.pem");
        let (listener, _) = bind_listener();
        let app = Router::new().route("/readyz", get(|| async { "ok" }));

        let error = serve_with_listener(
            listener,
            app,
            Some(TlsConfig {
                cert_path: missing_cert.display().to_string(),
                key_path: missing_key.display().to_string(),
                client_ca_cert: None,
            }),
            async {},
        )
        .await
        .expect_err("missing TLS assets should fail before serving");

        assert!(matches!(error, ServeError::TlsConfig(_)));

        let _ = std::fs::remove_dir_all(dir);
    }

    fn bind_listener() -> (TcpListener, std::net::SocketAddr) {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        (TcpListener::from_std(listener).unwrap(), address)
    }

    fn tls_client(ca_cert_pem: &str, identity: Option<Identity>) -> Client {
        super::ensure_crypto_provider_installed();
        let mut builder = Client::builder()
            .add_root_certificate(Certificate::from_pem(ca_cert_pem.as_bytes()).unwrap())
            .danger_accept_invalid_hostnames(true);
        if let Some(identity) = identity {
            builder = builder.identity(identity);
        }
        builder.build().unwrap()
    }

    struct TlsTestMaterials {
        dir: PathBuf,
        ca_cert_pem: String,
        server_cert_path: PathBuf,
        server_key_path: PathBuf,
        client_ca_cert_path: Option<PathBuf>,
        client_cert_pem: Option<String>,
        client_key_pem: Option<String>,
    }

    impl TlsTestMaterials {
        fn server_only(server_name: &str) -> Self {
            Self::new(server_name, None)
        }

        fn mutual_tls(server_name: &str, client_name: &str) -> Self {
            Self::new(server_name, Some(client_name))
        }

        fn new(server_name: &str, client_name: Option<&str>) -> Self {
            let dir = unique_temp_dir();
            let ca = certificate_authority("swarm-test-ca");
            let ca_cert_pem = ca.cert.pem();
            let server = leaf_certificate(server_name, &ca);

            let server_cert_path = dir.join("server-cert.pem");
            let server_key_path = dir.join("server-key.pem");
            std::fs::write(&server_cert_path, server.cert.pem()).unwrap();
            std::fs::write(&server_key_path, server.key_pair.serialize_pem()).unwrap();

            let (client_ca_cert_path, client_cert_pem, client_key_pem) =
                if let Some(client_name) = client_name {
                    let client = leaf_certificate(client_name, &ca);
                    let client_ca_cert_path = dir.join("client-ca.pem");
                    std::fs::write(&client_ca_cert_path, &ca_cert_pem).unwrap();
                    (
                        Some(client_ca_cert_path),
                        Some(client.cert.pem()),
                        Some(client.key_pair.serialize_pem()),
                    )
                } else {
                    (None, None, None)
                };

            Self {
                dir,
                ca_cert_pem,
                server_cert_path,
                server_key_path,
                client_ca_cert_path,
                client_cert_pem,
                client_key_pem,
            }
        }

        fn server_tls_config(&self) -> TlsConfig {
            TlsConfig {
                cert_path: self.server_cert_path.display().to_string(),
                key_path: self.server_key_path.display().to_string(),
                client_ca_cert: None,
            }
        }

        fn mtls_server_config(&self) -> TlsConfig {
            TlsConfig {
                cert_path: self.server_cert_path.display().to_string(),
                key_path: self.server_key_path.display().to_string(),
                client_ca_cert: self
                    .client_ca_cert_path
                    .as_ref()
                    .map(|path| path.display().to_string()),
            }
        }
    }

    impl Drop for TlsTestMaterials {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    struct CertificateAuthority {
        cert: rcgen::Certificate,
        key_pair: KeyPair,
    }

    struct LeafCertificate {
        cert: rcgen::Certificate,
        key_pair: KeyPair,
    }

    fn certificate_authority(common_name: &str) -> CertificateAuthority {
        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        let cert = params.self_signed(&key_pair).unwrap();
        CertificateAuthority { cert, key_pair }
    }

    fn leaf_certificate(common_name: &str, ca: &CertificateAuthority) -> LeafCertificate {
        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![common_name.to_string()]).unwrap();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        let cert = params.signed_by(&key_pair, &ca.cert, &ca.key_pair).unwrap();
        LeafCertificate { cert, key_pair }
    }

    fn unique_temp_dir() -> PathBuf {
        let counter = TLS_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "swarm-runtime-tls-test-{}-{}",
            std::process::id(),
            counter
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
