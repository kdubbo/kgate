#![allow(dead_code)]

use axum::http::Uri;
use axum::routing::any;
use axum::Router;
use dxgate_core::{
    Cluster, Endpoint, Listener, ListenerProtocol, PathMatch, Route, RouteMatch, RuntimeConfig,
    VirtualHost, WeightedCluster,
};
use dxgate_proxy::{ProxyServer, ProxyState};
use hyper::body;
use hyper::Client;
use std::net::{SocketAddr, TcpListener};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tokio::time::sleep;

pub struct TestTopology {
    pub proxy_addr: SocketAddr,
    proxy_task: JoinHandle<()>,
    backend_task: JoinHandle<()>,
}

impl Drop for TestTopology {
    fn drop(&mut self) {
        self.proxy_task.abort();
        self.backend_task.abort();
    }
}

pub async fn spawn_topology() -> TestTopology {
    let backend_addr = unused_addr();
    let proxy_addr = unused_addr();
    let backend_task = spawn_backend(backend_addr);

    wait_until_ok(backend_addr, "/health").await;

    let state = ProxyState::new(RuntimeConfig::empty("bootstrap"));
    state
        .apply_config(runtime_config(backend_addr))
        .await
        .unwrap();
    let proxy_task = tokio::spawn(async move {
        ProxyServer::new(state).serve(proxy_addr).await.unwrap();
    });

    let topology = TestTopology {
        proxy_addr,
        proxy_task,
        backend_task,
    };
    wait_until_ok(topology.proxy_addr, "/health").await;
    topology
}

pub async fn get_text(addr: SocketAddr, path: &str) -> (http::StatusCode, String) {
    let uri: Uri = format!("http://{addr}{path}").parse().unwrap();
    let response = Client::new().get(uri).await.unwrap();
    let status = response.status();
    let bytes = body::to_bytes(response.into_body()).await.unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

pub async fn run_concurrent_requests(addr: SocketAddr, requests: usize) -> Vec<Duration> {
    let client = Client::new();
    let mut tasks = Vec::with_capacity(requests);

    for i in 0..requests {
        let client = client.clone();
        let uri: Uri = format!("http://{addr}/perf/{i}").parse().unwrap();
        tasks.push(tokio::spawn(async move {
            let started = Instant::now();
            let response = client.get(uri).await.unwrap();
            assert!(response.status().is_success());
            let _ = body::to_bytes(response.into_body()).await.unwrap();
            started.elapsed()
        }));
    }

    let mut latencies = Vec::with_capacity(requests);
    for task in tasks {
        latencies.push(task.await.unwrap());
    }
    latencies
}

pub fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(default)
}

pub fn percentile(latencies: &mut [Duration], percentile: usize) -> Duration {
    latencies.sort_unstable();
    let rank = ((latencies.len() * percentile) + 99) / 100;
    latencies[rank.saturating_sub(1)]
}

fn spawn_backend(addr: SocketAddr) -> JoinHandle<()> {
    let app = Router::new()
        .route("/health", any(|| async { "ok" }))
        .fallback(any(|uri: Uri| async move {
            let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
            format!("dxgate example backend path={path}")
        }));

    tokio::spawn(async move {
        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await
            .unwrap();
    })
}

async fn wait_until_ok(addr: SocketAddr, path: &str) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Ok((status, _)) = try_get_text(addr, path).await {
            if status.is_success() {
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "server {addr}{path} did not become ready"
        );
        sleep(Duration::from_millis(25)).await;
    }
}

async fn try_get_text(
    addr: SocketAddr,
    path: &str,
) -> Result<(http::StatusCode, String), hyper::Error> {
    let uri: Uri = format!("http://{addr}{path}").parse().unwrap();
    let response = Client::new().get(uri).await?;
    let status = response.status();
    let bytes = body::to_bytes(response.into_body()).await?;
    Ok((status, String::from_utf8(bytes.to_vec()).unwrap()))
}

fn runtime_config(backend_addr: SocketAddr) -> RuntimeConfig {
    RuntimeConfig {
        version: "e2e".into(),
        listeners: vec![Listener {
            name: "http-80".into(),
            bind: "0.0.0.0:80".parse().unwrap(),
            protocol: ListenerProtocol::Http,
            virtual_hosts: vec![VirtualHost {
                name: "wildcard".into(),
                domains: vec!["*".into()],
                routes: vec![Route {
                    name: "default".into(),
                    matches: vec![RouteMatch {
                        path: PathMatch::Prefix("/".into()),
                        headers: vec![],
                    }],
                    weighted_clusters: vec![WeightedCluster {
                        name: "backend".into(),
                        weight: 100,
                    }],
                }],
            }],
            tls_secret: None,
        }],
        clusters: vec![Cluster {
            name: "backend".into(),
            endpoints: vec![Endpoint {
                address: backend_addr.ip().to_string(),
                port: backend_addr.port(),
                healthy: true,
                node_name: None,
            }],
            tls: None,
        }],
        secrets: vec![],
    }
}

fn unused_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}
