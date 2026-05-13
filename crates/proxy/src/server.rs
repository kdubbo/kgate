use crate::ProxyState;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, Response, StatusCode, Uri};
use axum::routing::any;
use axum::Router;
use dxgate_core::{Cluster, Endpoint, MatchInput, UpstreamTls, HTTP_LISTENER_PORT};
use hyper::client::HttpConnector;
use hyper::Client;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use rustls::client::{ServerCertVerified, ServerCertVerifier, WebPkiVerifier};
use rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore};
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tracing::{debug, info, warn};

type PlainClient = Client<HttpConnector, Body>;
type MtlsClient = Client<HttpsConnector<HttpConnector>, Body>;

#[derive(Clone)]
pub struct ProxyServer {
    state: ProxyState,
    clients: UpstreamClients,
}

impl ProxyServer {
    pub fn new(state: ProxyState) -> Self {
        Self {
            state,
            clients: UpstreamClients::from_env(),
        }
    }

    pub async fn serve(self, addr: SocketAddr) -> std::io::Result<()> {
        let app = Router::new().fallback(any(proxy_request)).with_state(self);
        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await
            .map_err(std::io::Error::other)
    }
}

async fn proxy_request(State(server): State<ProxyServer>, req: Request<Body>) -> Response<Body> {
    match forward(server, req).await {
        Ok(resp) => resp,
        Err((status, message)) => {
            warn!(status = status.as_u16(), %message, "request failed");
            Response::builder()
                .status(status)
                .body(Body::from(message))
                .unwrap_or_else(|_| Response::new(Body::from("proxy error")))
        }
    }
}

async fn forward(
    server: ProxyServer,
    mut req: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    let cfg = server.state.config().await;
    let host = host_header(req.headers()).unwrap_or("*");
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    let headers = header_pairs(req.headers());
    let input = MatchInput {
        host,
        path: &path,
        headers: &headers,
    };

    let weighted_clusters = cfg
        .route_for(HTTP_LISTENER_PORT, &input)
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?
        .weighted_clusters
        .clone();

    let weighted = server
        .state
        .pick_cluster(&weighted_clusters)
        .await
        .ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "route has no clusters".to_string(),
            )
        })?;

    let cluster = cfg
        .cluster(&weighted.name)
        .ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("cluster {} not found", weighted.name),
            )
        })?
        .clone();

    let endpoint = server
        .state
        .pick_endpoint(&cluster.name, &cluster.endpoints)
        .await
        .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;

    let tls = cluster.tls.as_ref();
    let scheme = if tls.is_some() { "https" } else { "http" };
    let upstream_uri = format!("{}://{}{}", scheme, endpoint_authority(&endpoint), path)
        .parse::<Uri>()
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("invalid upstream uri: {e}"),
            )
        })?;

    debug!(
        cluster = %cluster.name,
        endpoint = %endpoint.address,
        mtls = tls.is_some(),
        "forwarding request"
    );

    *req.uri_mut() = upstream_uri;
    req.headers_mut().remove(http::header::HOST);

    if let Some(tls) = tls {
        return server.clients.request_mtls(&cluster, tls, req).await;
    }
    server.clients.request_plain(req).await
}

fn endpoint_authority(endpoint: &Endpoint) -> String {
    if endpoint.address.contains(':') && !endpoint.address.starts_with('[') {
        format!("[{}]:{}", endpoint.address, endpoint.port)
    } else {
        format!("{}:{}", endpoint.address, endpoint.port)
    }
}

fn host_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|host| host.split(':').next().unwrap_or(host))
}

fn header_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect()
}

#[derive(Clone)]
struct UpstreamClients {
    plaintext: PlainClient,
    mtls: MtlsSupport,
}

impl UpstreamClients {
    fn from_env() -> Self {
        let mtls = match env::var("GRPC_XDS_BOOTSTRAP") {
            Ok(path) if !path.is_empty() => match MtlsClientPool::from_bootstrap(&path) {
                Ok(pool) => {
                    info!(bootstrap = %path, "loaded dxgate upstream mTLS bootstrap");
                    MtlsSupport::Available(Arc::new(pool))
                }
                Err(err) => {
                    warn!(bootstrap = %path, %err, "failed loading dxgate upstream mTLS bootstrap");
                    MtlsSupport::Error(Arc::from(err))
                }
            },
            _ => MtlsSupport::Disabled,
        };
        Self {
            plaintext: Client::new(),
            mtls,
        }
    }

    async fn request_plain(
        &self,
        req: Request<Body>,
    ) -> Result<Response<Body>, (StatusCode, String)> {
        self.plaintext
            .request(req)
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))
    }

    async fn request_mtls(
        &self,
        cluster: &Cluster,
        tls: &UpstreamTls,
        req: Request<Body>,
    ) -> Result<Response<Body>, (StatusCode, String)> {
        let client = match &self.mtls {
            MtlsSupport::Available(pool) => pool.client_for(tls).map_err(|err| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("cluster {} mTLS setup failed: {err}", cluster.name),
                )
            })?,
            MtlsSupport::Disabled => {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    format!(
                        "cluster {} requires mTLS but GRPC_XDS_BOOTSTRAP is not configured",
                        cluster.name
                    ),
                ));
            }
            MtlsSupport::Error(err) => {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    format!(
                        "cluster {} requires mTLS but bootstrap loading failed: {err}",
                        cluster.name
                    ),
                ));
            }
        };
        client
            .request(req)
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))
    }
}

#[derive(Clone)]
enum MtlsSupport {
    Disabled,
    Available(Arc<MtlsClientPool>),
    Error(Arc<str>),
}

struct MtlsClientPool {
    bootstrap: GrpcBootstrap,
    clients: Mutex<HashMap<String, MtlsClient>>,
}

impl MtlsClientPool {
    fn from_bootstrap(path: &str) -> Result<Self, String> {
        let file =
            File::open(path).map_err(|e| format!("open gRPC xDS bootstrap {}: {e}", path))?;
        let bootstrap: GrpcBootstrap = serde_json::from_reader(file)
            .map_err(|e| format!("parse gRPC xDS bootstrap {}: {e}", path))?;
        Ok(Self {
            bootstrap,
            clients: Mutex::new(HashMap::new()),
        })
    }

    fn client_for(&self, tls: &UpstreamTls) -> Result<MtlsClient, String> {
        let key = mtls_cache_key(tls);
        let mut clients = self
            .clients
            .lock()
            .map_err(|_| "mTLS client cache lock poisoned".to_string())?;
        if let Some(client) = clients.get(&key) {
            return Ok(client.clone());
        }

        let config = self.tls_config(tls)?;
        let builder = HttpsConnectorBuilder::new()
            .with_tls_config(config)
            .https_only();
        let builder = match &tls.sni {
            Some(sni) if !sni.is_empty() => builder.with_server_name(sni.clone()),
            _ => builder,
        };
        let connector = builder.enable_http1().build();
        let client = Client::builder().build::<_, Body>(connector);
        clients.insert(key, client.clone());
        Ok(client)
    }

    fn tls_config(&self, tls: &UpstreamTls) -> Result<ClientConfig, String> {
        let cert_provider = tls.certificate_provider.as_deref().unwrap_or("default");
        let root_provider = tls.validation_provider.as_deref().unwrap_or("default");
        let cert_config = self.bootstrap.provider(cert_provider)?;
        let root_config = self.bootstrap.provider(root_provider)?;
        let cert_file = cert_config.required_path("certificate_file", cert_provider)?;
        let key_file = cert_config.required_path("private_key_file", cert_provider)?;
        let ca_file = root_config.required_path("ca_certificate_file", root_provider)?;

        let certs = load_certs(cert_file, "data-plane client certificate")?;
        let key = load_private_key(key_file)?;
        let roots = load_roots(ca_file)?;
        let verifier = Arc::new(SpiffeCompatibleVerifier {
            inner: WebPkiVerifier::new(roots, None),
        });
        ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(certs, key)
            .map_err(|e| format!("build data-plane mTLS client config: {e}"))
    }
}

#[derive(Debug, Deserialize)]
struct GrpcBootstrap {
    #[serde(default)]
    certificate_providers: HashMap<String, CertificateProvider>,
}

impl GrpcBootstrap {
    fn provider(&self, name: &str) -> Result<&FileWatcherConfig, String> {
        self.certificate_providers
            .get(name)
            .map(|provider| &provider.config)
            .ok_or_else(|| format!("certificate_providers[{name:?}] not found"))
    }
}

#[derive(Debug, Deserialize)]
struct CertificateProvider {
    config: FileWatcherConfig,
}

#[derive(Debug, Deserialize)]
struct FileWatcherConfig {
    certificate_file: Option<PathBuf>,
    private_key_file: Option<PathBuf>,
    ca_certificate_file: Option<PathBuf>,
}

impl FileWatcherConfig {
    fn required_path(&self, field: &str, provider: &str) -> Result<&Path, String> {
        let path = match field {
            "certificate_file" => &self.certificate_file,
            "private_key_file" => &self.private_key_file,
            "ca_certificate_file" => &self.ca_certificate_file,
            _ => return Err(format!("unknown file watcher field {field}")),
        };
        path.as_deref().ok_or_else(|| {
            format!("certificate_providers[{provider:?}].config.{field} is required")
        })
    }
}

fn mtls_cache_key(tls: &UpstreamTls) -> String {
    format!(
        "{}|{}|{}|{}",
        tls.sni.as_deref().unwrap_or_default(),
        tls.certificate_provider.as_deref().unwrap_or("default"),
        tls.validation_provider.as_deref().unwrap_or("default"),
        tls.alpn_protocols.join(",")
    )
}

fn load_certs(path: &Path, label: &str) -> Result<Vec<Certificate>, String> {
    let file = File::open(path).map_err(|e| format!("open {label} {}: {e}", path.display()))?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|e| format!("parse {label} {}: {e}", path.display()))?
        .into_iter()
        .map(Certificate)
        .collect::<Vec<_>>();
    if certs.is_empty() {
        return Err(format!(
            "parse {label} {}: no certificates found",
            path.display()
        ));
    }
    Ok(certs)
}

fn load_roots(path: &Path) -> Result<RootCertStore, String> {
    let certs = load_certs(path, "data-plane CA certificate")?;
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots
            .add(&cert)
            .map_err(|e| format!("add data-plane CA certificate {}: {e}", path.display()))?;
    }
    Ok(roots)
}

fn load_private_key(path: &Path) -> Result<PrivateKey, String> {
    if let Some(key) = load_private_keys(path, KeyFormat::Pkcs8)?
        .into_iter()
        .next()
    {
        return Ok(PrivateKey(key));
    }
    if let Some(key) = load_private_keys(path, KeyFormat::Rsa)?.into_iter().next() {
        return Ok(PrivateKey(key));
    }
    Err(format!(
        "parse data-plane client private key {}: no PKCS8 or RSA keys found",
        path.display()
    ))
}

enum KeyFormat {
    Pkcs8,
    Rsa,
}

fn load_private_keys(path: &Path, format: KeyFormat) -> Result<Vec<Vec<u8>>, String> {
    let file = File::open(path)
        .map_err(|e| format!("open data-plane client private key {}: {e}", path.display()))?;
    let mut reader = BufReader::new(file);
    match format {
        KeyFormat::Pkcs8 => rustls_pemfile::pkcs8_private_keys(&mut reader),
        KeyFormat::Rsa => rustls_pemfile::rsa_private_keys(&mut reader),
    }
    .map_err(|e| {
        format!(
            "parse data-plane client private key {}: {e}",
            path.display()
        )
    })
}

struct SpiffeCompatibleVerifier {
    inner: WebPkiVerifier,
}

impl std::fmt::Debug for SpiffeCompatibleVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeCompatibleVerifier").finish()
    }
}

impl ServerCertVerifier for SpiffeCompatibleVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &rustls::ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            scts,
            ocsp_response,
            now,
        ) {
            Ok(verified) => Ok(verified),
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName)) => {
                Ok(ServerCertVerified::assertion())
            }
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::body;
    use rcgen::{
        BasicConstraints, Certificate as RcgenCertificate, CertificateParams, DistinguishedName,
        DnType, IsCa,
    };
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    #[test]
    fn parses_grpc_xds_bootstrap_file_watcher_provider() {
        let bootstrap = serde_json::from_str::<GrpcBootstrap>(
            r#"{
              "certificate_providers": {
                "default": {
                  "plugin_name": "file_watcher",
                  "config": {
                    "certificate_file": "/etc/dubbo/proxy/cert-chain.pem",
                    "private_key_file": "/etc/dubbo/proxy/key.pem",
                    "ca_certificate_file": "/etc/dubbo/proxy/root-cert.pem"
                  }
                }
              }
            }"#,
        )
        .unwrap();

        let provider = bootstrap.provider("default").unwrap();
        assert_eq!(
            provider
                .required_path("certificate_file", "default")
                .unwrap(),
            Path::new("/etc/dubbo/proxy/cert-chain.pem")
        );
        assert_eq!(
            provider
                .required_path("private_key_file", "default")
                .unwrap(),
            Path::new("/etc/dubbo/proxy/key.pem")
        );
        assert_eq!(
            provider
                .required_path("ca_certificate_file", "default")
                .unwrap(),
            Path::new("/etc/dubbo/proxy/root-cert.pem")
        );
    }

    #[tokio::test]
    async fn mtls_client_connects_with_bootstrap_certificate() {
        let ca = test_ca();
        let server_cert = signed_cert("nginx.app.svc.cluster.local");
        let client_cert = signed_cert("dxgate.default.svc.cluster.local");
        let dir = temp_dir("dxgate-mtls");
        fs::create_dir_all(&dir).unwrap();

        let cert_chain = dir.join("cert-chain.pem");
        let key = dir.join("key.pem");
        let root = dir.join("root-cert.pem");
        let bootstrap = dir.join("grpc-bootstrap.json");
        fs::write(
            &cert_chain,
            client_cert.serialize_pem_with_signer(&ca).unwrap(),
        )
        .unwrap();
        fs::write(&key, client_cert.serialize_private_key_pem()).unwrap();
        fs::write(&root, ca.serialize_pem().unwrap()).unwrap();
        fs::write(
            &bootstrap,
            serde_json::json!({
                "certificate_providers": {
                    "default": {
                        "plugin_name": "file_watcher",
                        "config": {
                            "certificate_file": cert_chain,
                            "private_key_file": key,
                            "ca_certificate_file": root
                        }
                    }
                }
            })
            .to_string(),
        )
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config(&ca, &server_cert)));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut buf = [0; 256];
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                .await
                .unwrap();
        });

        let pool = MtlsClientPool::from_bootstrap(bootstrap.to_str().unwrap()).unwrap();
        let client = pool
            .client_for(&UpstreamTls {
                sni: Some("nginx.app.svc.cluster.local".into()),
                certificate_provider: None,
                validation_provider: None,
                alpn_protocols: vec!["h2".into()],
            })
            .unwrap();
        let uri = format!("https://127.0.0.1:{}/", addr.port())
            .parse()
            .unwrap();
        let response = client.get(uri).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body::to_bytes(response.into_body()).await.unwrap();
        assert_eq!(&bytes[..], b"ok");

        server.await.unwrap();
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn mtls_cache_key_tracks_provider_and_alpn() {
        let tls = UpstreamTls {
            sni: Some("nginx.app.svc.cluster.local".into()),
            certificate_provider: Some("workload".into()),
            validation_provider: Some("roots".into()),
            alpn_protocols: vec!["h2".into(), "http/1.1".into()],
        };

        assert_eq!(
            mtls_cache_key(&tls),
            "nginx.app.svc.cluster.local|workload|roots|h2,http/1.1"
        );
    }

    fn test_ca() -> RcgenCertificate {
        let mut params = CertificateParams::new(vec!["dubbo.test".into()]);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "dubbo test ca");
        RcgenCertificate::from_params(params).unwrap()
    }

    fn signed_cert(dns_name: &str) -> RcgenCertificate {
        let mut params = CertificateParams::new(vec![dns_name.into()]);
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, dns_name);
        RcgenCertificate::from_params(params).unwrap()
    }

    fn server_config(
        ca: &RcgenCertificate,
        server_cert: &RcgenCertificate,
    ) -> rustls::ServerConfig {
        let mut client_roots = RootCertStore::empty();
        client_roots
            .add(&Certificate(ca.serialize_der().unwrap()))
            .unwrap();
        let client_verifier = Arc::new(rustls::server::AllowAnyAuthenticatedClient::new(
            client_roots,
        ));
        rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(
                vec![Certificate(
                    server_cert.serialize_der_with_signer(ca).unwrap(),
                )],
                PrivateKey(server_cert.serialize_private_key_der()),
            )
            .unwrap()
    }

    fn temp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nanos}"))
    }
}
