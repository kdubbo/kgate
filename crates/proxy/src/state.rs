use dxgate_core::{ConfigConflict, DxgateError, Endpoint, Result, RuntimeConfig, WeightedCluster};
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct ProxyState {
    inner: Arc<Inner>,
}

struct Inner {
    config: RwLock<RuntimeConfig>,
    conflicts: RwLock<Vec<ConfigConflict>>,
    ready: AtomicBool,
    picker_counter: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Readiness {
    pub ready: bool,
    pub version: String,
    pub conflicts: Vec<ConfigConflict>,
}

impl ProxyState {
    pub fn new(initial: RuntimeConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                config: RwLock::new(initial),
                conflicts: RwLock::new(Vec::new()),
                ready: AtomicBool::new(false),
                picker_counter: AtomicU64::new(0),
            }),
        }
    }

    pub async fn apply_config(
        &self,
        cfg: RuntimeConfig,
    ) -> std::result::Result<(), Vec<ConfigConflict>> {
        match cfg.validate() {
            Ok(()) => {
                *self.inner.config.write().await = cfg;
                self.inner.conflicts.write().await.clear();
                self.inner.ready.store(true, Ordering::SeqCst);
                Ok(())
            }
            Err(conflicts) => {
                *self.inner.conflicts.write().await = conflicts.clone();
                self.inner.ready.store(false, Ordering::SeqCst);
                Err(conflicts)
            }
        }
    }

    pub async fn config(&self) -> RuntimeConfig {
        self.inner.config.read().await.clone()
    }

    pub async fn readiness(&self) -> Readiness {
        Readiness {
            ready: self.inner.ready.load(Ordering::SeqCst),
            version: self.inner.config.read().await.version.clone(),
            conflicts: self.inner.conflicts.read().await.clone(),
        }
    }

    pub async fn pick_cluster<'a>(
        &self,
        clusters: &'a [WeightedCluster],
    ) -> Option<&'a WeightedCluster> {
        let total: u32 = clusters.iter().map(|c| c.weight).sum();
        if total == 0 {
            return clusters.first();
        }
        let next = self.inner.picker_counter.fetch_add(1, Ordering::Relaxed) as u32 % total;
        let mut cursor = 0;
        clusters.iter().find(|cluster| {
            cursor += cluster.weight;
            next < cursor
        })
    }

    pub async fn pick_endpoint<'a>(
        &self,
        cluster_name: &str,
        endpoints: &'a [Endpoint],
    ) -> Result<&'a Endpoint> {
        let healthy: Vec<&Endpoint> = endpoints.iter().filter(|ep| ep.healthy).collect();
        if healthy.is_empty() {
            return Err(DxgateError::NoHealthyEndpoints(cluster_name.to_string()));
        }
        let idx =
            self.inner.picker_counter.fetch_add(1, Ordering::Relaxed) as usize % healthy.len();
        Ok(healthy[idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dxgate_core::{
        Cluster, Listener, ListenerProtocol, PathMatch, Route, RouteMatch, VirtualHost,
    };

    fn valid_config(version: &str) -> RuntimeConfig {
        RuntimeConfig {
            version: version.into(),
            listeners: vec![Listener {
                name: "http".into(),
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
                    address: "127.0.0.1".into(),
                    port: 8080,
                    healthy: true,
                    node_name: None,
                }],
                tls: None,
            }],
            secrets: vec![],
        }
    }

    #[tokio::test]
    async fn apply_config_updates_readiness_and_conflicts() {
        let state = ProxyState::new(RuntimeConfig::empty("bootstrap"));
        state.apply_config(valid_config("ok")).await.unwrap();

        let readiness = state.readiness().await;
        assert!(readiness.ready);
        assert_eq!(readiness.version, "ok");
        assert!(readiness.conflicts.is_empty());

        let mut invalid = valid_config("bad");
        invalid.clusters.clear();
        let conflicts = state.apply_config(invalid).await.unwrap_err();

        let readiness = state.readiness().await;
        assert!(!readiness.ready);
        assert_eq!(readiness.conflicts, conflicts);
        assert_eq!(readiness.conflicts[0].kind, "missing-cluster");
    }

    #[tokio::test]
    async fn weighted_cluster_picker_is_deterministic() {
        let state = ProxyState::new(RuntimeConfig::empty("test"));
        let clusters = vec![
            WeightedCluster {
                name: "a".into(),
                weight: 2,
            },
            WeightedCluster {
                name: "b".into(),
                weight: 1,
            },
        ];
        let mut names = Vec::new();

        for _ in 0..6 {
            names.push(state.pick_cluster(&clusters).await.unwrap().name.clone());
        }

        assert_eq!(names, ["a", "a", "b", "a", "a", "b"]);
    }

    #[tokio::test]
    async fn endpoint_picker_skips_unhealthy_endpoints() {
        let state = ProxyState::new(RuntimeConfig::empty("test"));
        let endpoints = vec![
            Endpoint {
                address: "10.0.0.1".into(),
                port: 8080,
                healthy: false,
                node_name: None,
            },
            Endpoint {
                address: "10.0.0.2".into(),
                port: 8080,
                healthy: true,
                node_name: None,
            },
        ];

        let endpoint = state.pick_endpoint("backend", &endpoints).await.unwrap();
        assert_eq!(endpoint.address, "10.0.0.2");

        let unhealthy = vec![Endpoint {
            address: "10.0.0.3".into(),
            port: 8080,
            healthy: false,
            node_name: None,
        }];
        assert!(state.pick_endpoint("backend", &unhealthy).await.is_err());
    }
}
