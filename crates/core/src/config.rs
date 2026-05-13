use crate::{ConfigConflict, DxgateError, MatchInput, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

pub const HTTP_LISTENER_PORT: u16 = 80;
pub const HTTPS_LISTENER_PORT: u16 = 443;
pub const ADMIN_PORT: u16 = 15021;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub version: String,
    #[serde(default)]
    pub listeners: Vec<Listener>,
    #[serde(default)]
    pub clusters: Vec<Cluster>,
    #[serde(default)]
    pub secrets: Vec<TlsSecret>,
}

impl RuntimeConfig {
    pub fn empty(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            listeners: Vec::new(),
            clusters: Vec::new(),
            secrets: Vec::new(),
        }
    }

    pub fn validate(&self) -> std::result::Result<(), Vec<ConfigConflict>> {
        let mut conflicts = Vec::new();
        let mut listener_names = BTreeSet::new();
        let mut binds: BTreeMap<SocketAddr, (&str, ListenerProtocol, bool)> = BTreeMap::new();

        for listener in &self.listeners {
            if !listener_names.insert(listener.name.as_str()) {
                conflicts.push(ConfigConflict::new(
                    "duplicate-listener",
                    format!("listener {} is defined more than once", listener.name),
                ));
            }

            let tls_enabled = listener.tls_secret.is_some();
            if let Some((existing_name, existing_protocol, existing_tls)) = binds.insert(
                listener.bind,
                (&listener.name, listener.protocol, tls_enabled),
            ) {
                if existing_protocol != listener.protocol || existing_tls != tls_enabled {
                    conflicts.push(ConfigConflict::new(
                        "listener-bind-conflict",
                        format!(
                            "listeners {} and {} both bind {} with incompatible protocol or TLS mode",
                            existing_name, listener.name, listener.bind
                        ),
                    ));
                }
            }
        }

        let mut clusters = BTreeSet::new();
        for cluster in &self.clusters {
            if !clusters.insert(cluster.name.as_str()) {
                conflicts.push(ConfigConflict::new(
                    "duplicate-cluster",
                    format!("cluster {} is defined more than once", cluster.name),
                ));
            }
        }

        for listener in &self.listeners {
            for host in &listener.virtual_hosts {
                for route in &host.routes {
                    if route.weighted_clusters.is_empty() {
                        conflicts.push(ConfigConflict::new(
                            "empty-route-destination",
                            format!(
                                "route {} on listener {} has no weighted clusters",
                                route.name, listener.name
                            ),
                        ));
                    }
                    for dst in &route.weighted_clusters {
                        if !clusters.contains(dst.name.as_str()) {
                            conflicts.push(ConfigConflict::new(
                                "missing-cluster",
                                format!(
                                    "route {} references missing cluster {}",
                                    route.name, dst.name
                                ),
                            ));
                        }
                    }
                }
            }
        }

        if conflicts.is_empty() {
            Ok(())
        } else {
            Err(conflicts)
        }
    }

    pub fn listener_by_port(&self, port: u16) -> Option<&Listener> {
        self.listeners.iter().find(|l| l.bind.port() == port)
    }

    pub fn cluster(&self, name: &str) -> Option<&Cluster> {
        self.clusters.iter().find(|c| c.name == name)
    }

    pub fn route_for<'a>(&'a self, port: u16, input: &MatchInput<'_>) -> Result<&'a Route> {
        let listener = self
            .listener_by_port(port)
            .ok_or_else(|| DxgateError::RouteNotFound {
                host: input.host.to_string(),
                path: input.path.to_string(),
            })?;

        listener
            .virtual_hosts
            .iter()
            .filter(|vh| vh.matches_host(input.host))
            .flat_map(|vh| vh.routes.iter())
            .find(|route| route.matches(input))
            .ok_or_else(|| DxgateError::RouteNotFound {
                host: input.host.to_string(),
                path: input.path.to_string(),
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listener {
    pub name: String,
    pub bind: SocketAddr,
    pub protocol: ListenerProtocol,
    #[serde(default)]
    pub virtual_hosts: Vec<VirtualHost>,
    #[serde(default)]
    pub tls_secret: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListenerProtocol {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualHost {
    pub name: String,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub routes: Vec<Route>,
}

impl VirtualHost {
    pub fn matches_host(&self, host: &str) -> bool {
        self.domains.iter().any(|domain| {
            domain == "*"
                || domain.eq_ignore_ascii_case(host)
                || domain
                    .strip_prefix("*.")
                    .map(|suffix| host.ends_with(suffix))
                    .unwrap_or(false)
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    pub name: String,
    #[serde(default)]
    pub matches: Vec<RouteMatch>,
    #[serde(default)]
    pub weighted_clusters: Vec<WeightedCluster>,
}

impl Route {
    pub fn matches(&self, input: &MatchInput<'_>) -> bool {
        self.matches.is_empty() || self.matches.iter().any(|m| m.matches(input))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteMatch {
    #[serde(default)]
    pub path: PathMatch,
    #[serde(default)]
    pub headers: Vec<HeaderMatch>,
}

impl RouteMatch {
    pub fn matches(&self, input: &MatchInput<'_>) -> bool {
        self.path.matches(input.path) && self.headers.iter().all(|h| h.matches(input))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "lowercase")]
pub enum PathMatch {
    Prefix(String),
    Exact(String),
}

impl Default for PathMatch {
    fn default() -> Self {
        Self::Prefix("/".to_string())
    }
}

impl PathMatch {
    pub fn matches(&self, path: &str) -> bool {
        match self {
            Self::Prefix(prefix) => path.starts_with(prefix),
            Self::Exact(exact) => path == exact,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderMatch {
    pub name: String,
    pub value: String,
}

impl HeaderMatch {
    pub fn matches(&self, input: &MatchInput<'_>) -> bool {
        input
            .headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case(&self.name) && value == &self.value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeightedCluster {
    pub name: String,
    pub weight: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cluster {
    pub name: String,
    #[serde(default)]
    pub endpoints: Vec<Endpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<UpstreamTls>,
}

impl Cluster {
    pub fn healthy_endpoints(&self) -> impl Iterator<Item = &Endpoint> {
        self.endpoints.iter().filter(|ep| ep.healthy)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamTls {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn_protocols: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub address: String,
    pub port: u16,
    #[serde(default = "default_true")]
    pub healthy: bool,
    #[serde(default)]
    pub node_name: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsSecret {
    pub name: String,
    pub certificate_chain_pem: String,
    pub private_key_pem: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_listener_conflict() {
        let bind = "0.0.0.0:80".parse().unwrap();
        let cfg = RuntimeConfig {
            version: "test".into(),
            listeners: vec![
                Listener {
                    name: "http".into(),
                    bind,
                    protocol: ListenerProtocol::Http,
                    virtual_hosts: vec![],
                    tls_secret: None,
                },
                Listener {
                    name: "https".into(),
                    bind,
                    protocol: ListenerProtocol::Https,
                    virtual_hosts: vec![],
                    tls_secret: Some("secret".into()),
                },
            ],
            clusters: vec![],
            secrets: vec![],
        };

        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validates_missing_weighted_cluster_references() {
        let cfg = RuntimeConfig {
            version: "test".into(),
            listeners: vec![Listener {
                name: "http".into(),
                bind: "0.0.0.0:80".parse().unwrap(),
                protocol: ListenerProtocol::Http,
                virtual_hosts: vec![VirtualHost {
                    name: "wildcard".into(),
                    domains: vec!["*".into()],
                    routes: vec![Route {
                        name: "missing".into(),
                        matches: vec![RouteMatch {
                            path: PathMatch::Prefix("/".into()),
                            headers: vec![],
                        }],
                        weighted_clusters: vec![WeightedCluster {
                            name: "missing-cluster".into(),
                            weight: 100,
                        }],
                    }],
                }],
                tls_secret: None,
            }],
            clusters: vec![],
            secrets: vec![],
        };

        let conflicts = cfg.validate().unwrap_err();
        assert_eq!(conflicts[0].kind, "missing-cluster");
    }

    #[test]
    fn routes_by_host_path_and_header_match() {
        let cfg = RuntimeConfig {
            version: "test".into(),
            listeners: vec![Listener {
                name: "http".into(),
                bind: "0.0.0.0:80".parse().unwrap(),
                protocol: ListenerProtocol::Http,
                virtual_hosts: vec![VirtualHost {
                    name: "example".into(),
                    domains: vec!["*.example.com".into()],
                    routes: vec![
                        Route {
                            name: "admin".into(),
                            matches: vec![RouteMatch {
                                path: PathMatch::Exact("/admin".into()),
                                headers: vec![HeaderMatch {
                                    name: "x-env".into(),
                                    value: "prod".into(),
                                }],
                            }],
                            weighted_clusters: vec![WeightedCluster {
                                name: "admin".into(),
                                weight: 100,
                            }],
                        },
                        Route {
                            name: "default".into(),
                            matches: vec![RouteMatch {
                                path: PathMatch::Prefix("/".into()),
                                headers: vec![],
                            }],
                            weighted_clusters: vec![WeightedCluster {
                                name: "default".into(),
                                weight: 100,
                            }],
                        },
                    ],
                }],
                tls_secret: None,
            }],
            clusters: vec![
                Cluster {
                    name: "admin".into(),
                    endpoints: vec![],
                    tls: None,
                },
                Cluster {
                    name: "default".into(),
                    endpoints: vec![],
                    tls: None,
                },
            ],
            secrets: vec![],
        };

        let headers = vec![("x-env".to_string(), "prod".to_string())];
        let route = cfg
            .route_for(
                HTTP_LISTENER_PORT,
                &MatchInput {
                    host: "api.example.com",
                    path: "/admin",
                    headers: &headers,
                },
            )
            .unwrap();
        assert_eq!(route.name, "admin");

        let route = cfg
            .route_for(
                HTTP_LISTENER_PORT,
                &MatchInput {
                    host: "api.example.com",
                    path: "/users",
                    headers: &[],
                },
            )
            .unwrap();
        assert_eq!(route.name, "default");

        assert!(cfg
            .route_for(
                HTTP_LISTENER_PORT,
                &MatchInput {
                    host: "api.other.test",
                    path: "/users",
                    headers: &[],
                },
            )
            .is_err());
    }
}
