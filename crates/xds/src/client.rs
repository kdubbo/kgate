use crate::proto::cluster::v1 as xds_cluster;
use crate::proto::core::v1 as xds_core;
use crate::proto::endpoint::v1 as xds_endpoint;
use crate::proto::extensions::filters::network::http_connection_manager::v1 as xds_hcm;
use crate::proto::extensions::transport_sockets::tls::v1 as xds_tls;
use crate::proto::listener::v1 as xds_listener;
use crate::proto::route::v1 as xds_route;
use crate::proto::service::discovery::v1::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use crate::proto::service::discovery::v1::{DiscoveryRequest, DiscoveryResponse};
use dxgate_core::{
    Cluster, Endpoint as RuntimeEndpoint, HeaderMatch, Listener, ListenerProtocol, PathMatch,
    Route, RouteMatch, RouterIdentity, RuntimeConfig, UpstreamTls, VirtualHost, WeightedCluster,
};
use prost::Message;
use prost_types::{value::Kind, Struct, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{mpsc, watch};
use tokio::time;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Endpoint};
use tracing::{debug, info, warn};

const CLUSTER_TYPE: &str = "type.googleapis.com/cluster.v1.Cluster";
const ENDPOINT_TYPE: &str = "type.googleapis.com/endpoint.v1.ClusterLoadAssignment";
const LISTENER_TYPE: &str = "type.googleapis.com/listener.v1.Listener";
const ROUTE_TYPE: &str = "type.googleapis.com/route.v1.RouteConfiguration";
const MAX_DECODING_MESSAGE_SIZE: usize = 32 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum XdsError {
    #[error("invalid xDS endpoint {endpoint}: {source}")]
    InvalidEndpoint {
        endpoint: String,
        source: tonic::transport::Error,
    },

    #[error("failed connecting to xDS endpoint {endpoint}: {source}")]
    Connect {
        endpoint: String,
        source: tonic::transport::Error,
    },

    #[error("failed opening ADS stream: {0}")]
    StreamOpen(tonic::Status),

    #[error("ADS stream receive failed: {0}")]
    StreamReceive(tonic::Status),

    #[error("ADS request channel is closed")]
    RequestChannelClosed,

    #[error("failed decoding {type_url} resource: {source}")]
    Decode {
        type_url: String,
        source: prost::DecodeError,
    },

    #[error("runtime config watcher is closed")]
    RuntimeConfigClosed,
}

#[derive(Debug, Clone)]
pub struct XdsClientConfig {
    pub endpoint: String,
    pub identity: RouterIdentity,
    pub listener_names: Vec<String>,
    pub reconnect_delay: Duration,
}

pub struct XdsClient {
    cfg: XdsClientConfig,
}

impl XdsClient {
    pub fn new(cfg: XdsClientConfig) -> Self {
        Self { cfg }
    }

    pub async fn connect_channel(&self) -> Result<Channel, XdsError> {
        let endpoint = Endpoint::from_shared(self.cfg.endpoint.clone()).map_err(|source| {
            XdsError::InvalidEndpoint {
                endpoint: self.cfg.endpoint.clone(),
                source,
            }
        })?;

        endpoint
            .connect()
            .await
            .map_err(|source| XdsError::Connect {
                endpoint: self.cfg.endpoint.clone(),
                source,
            })
    }

    pub async fn run(self, config_tx: watch::Sender<RuntimeConfig>) -> Result<(), XdsError> {
        loop {
            match self.run_once(&config_tx).await {
                Ok(()) => warn!("ADS stream ended"),
                Err(err @ XdsError::InvalidEndpoint { .. }) => return Err(err),
                Err(err) => warn!(%err, "ADS stream failed"),
            }
            time::sleep(self.cfg.reconnect_delay).await;
        }
    }

    async fn run_once(&self, config_tx: &watch::Sender<RuntimeConfig>) -> Result<(), XdsError> {
        let channel = self.connect_channel().await?;
        let node = self.node();
        let mut ads = AggregatedDiscoveryServiceClient::new(channel)
            .max_decoding_message_size(MAX_DECODING_MESSAGE_SIZE);
        let (request_tx, request_rx) = mpsc::channel(32);
        let mut state = AdsState::default();

        let listener_names = sorted_unique(self.cfg.listener_names.clone());
        state.set_subscription(LISTENER_TYPE, listener_names.clone());
        send_discovery_request(&request_tx, &node, LISTENER_TYPE, listener_names, "", "").await?;

        let response = ads
            .stream_aggregated_resources(ReceiverStream::new(request_rx))
            .await
            .map_err(XdsError::StreamOpen)?;
        let mut stream = response.into_inner();

        info!(
            node_id = %self.cfg.identity.node_id(),
            endpoint = %self.cfg.endpoint,
            listeners = ?self.cfg.listener_names,
            "connected dxgate router to dubbod ADS endpoint"
        );

        while let Some(resp) = stream.message().await.map_err(XdsError::StreamReceive)? {
            let updates = state.apply_response(&resp)?;
            send_discovery_request(
                &request_tx,
                &node,
                &resp.type_url,
                state.subscription(&resp.type_url),
                &resp.version_info,
                &resp.nonce,
            )
            .await?;

            for (type_url, names) in updates.subscriptions() {
                if state.set_subscription(type_url, names.clone()) {
                    send_discovery_request(&request_tx, &node, type_url, names, "", "").await?;
                }
            }

            let cfg = state.runtime_config(&resp.version_info);
            match cfg.validate() {
                Ok(()) => {
                    if cfg != *config_tx.borrow() {
                        let version = cfg.version.clone();
                        config_tx
                            .send(cfg)
                            .map_err(|_| XdsError::RuntimeConfigClosed)?;
                        info!(version = %version, "applied ADS runtime config");
                    }
                }
                Err(conflicts) => {
                    debug!(?conflicts, "ADS runtime config is not complete yet");
                }
            }
        }

        Ok(())
    }

    fn node(&self) -> xds_core::Node {
        let metadata = self.cfg.identity.metadata();
        let mut fields = BTreeMap::new();
        fields.insert("GENERATOR".to_string(), string_value(metadata.generator));
        fields.insert("CLUSTER_ID".to_string(), string_value(metadata.cluster_id));
        fields.insert("NAMESPACE".to_string(), string_value(metadata.namespace));
        if let Some(node_name) = metadata.node_name {
            fields.insert("KUBE_NODE_NAME".to_string(), string_value(node_name));
        }

        xds_core::Node {
            id: self.cfg.identity.node_id(),
            cluster: self.cfg.identity.cluster_id.clone(),
            metadata: Some(Struct { fields }),
            locality: None,
        }
    }
}

async fn send_discovery_request(
    request_tx: &mpsc::Sender<DiscoveryRequest>,
    node: &xds_core::Node,
    type_url: &str,
    resource_names: Vec<String>,
    version_info: &str,
    response_nonce: &str,
) -> Result<(), XdsError> {
    request_tx
        .send(DiscoveryRequest {
            version_info: version_info.to_string(),
            node: Some(node.clone()),
            resource_names,
            type_url: type_url.to_string(),
            response_nonce: response_nonce.to_string(),
            error_detail: None,
        })
        .await
        .map_err(|_| XdsError::RequestChannelClosed)
}

fn string_value(value: String) -> Value {
    Value {
        kind: Some(Kind::StringValue(value)),
    }
}

#[derive(Default)]
struct AdsState {
    subscriptions: BTreeMap<String, Vec<String>>,
    listeners: BTreeMap<String, ListenerSnapshot>,
    routes: BTreeMap<String, Vec<VirtualHost>>,
    clusters: BTreeMap<String, ClusterSnapshot>,
    endpoints: BTreeMap<String, Vec<RuntimeEndpoint>>,
}

impl AdsState {
    fn apply_response(&mut self, resp: &DiscoveryResponse) -> Result<DiscoveryUpdates, XdsError> {
        match resp.type_url.as_str() {
            LISTENER_TYPE => self.apply_listeners(&resp.resources),
            ROUTE_TYPE => self.apply_routes(&resp.resources),
            CLUSTER_TYPE => self.apply_clusters(&resp.resources),
            ENDPOINT_TYPE => self.apply_endpoints(&resp.resources),
            _ => Ok(DiscoveryUpdates::default()),
        }
    }

    fn apply_listeners(
        &mut self,
        resources: &[prost_types::Any],
    ) -> Result<DiscoveryUpdates, XdsError> {
        let requested = self.subscription(LISTENER_TYPE);
        prune_requested(&mut self.listeners, &requested);
        for resource in resources {
            let listener = decode_resource::<xds_listener::Listener>(LISTENER_TYPE, resource)?;
            let snapshot = listener_snapshot(listener)?;
            self.listeners
                .insert(snapshot.listener.name.clone(), snapshot);
        }

        Ok(DiscoveryUpdates {
            route_names: self.route_names(),
            ..DiscoveryUpdates::default()
        })
    }

    fn apply_routes(
        &mut self,
        resources: &[prost_types::Any],
    ) -> Result<DiscoveryUpdates, XdsError> {
        let requested = self.subscription(ROUTE_TYPE);
        prune_requested(&mut self.routes, &requested);
        for resource in resources {
            let route = decode_resource::<xds_route::RouteConfiguration>(ROUTE_TYPE, resource)?;
            self.routes.insert(
                route.name.clone(),
                convert_virtual_hosts(&route.virtual_hosts),
            );
        }

        Ok(DiscoveryUpdates {
            cluster_names: self.cluster_names(),
            ..DiscoveryUpdates::default()
        })
    }

    fn apply_clusters(
        &mut self,
        resources: &[prost_types::Any],
    ) -> Result<DiscoveryUpdates, XdsError> {
        let requested = self.subscription(CLUSTER_TYPE);
        prune_requested(&mut self.clusters, &requested);
        for resource in resources {
            let cluster = decode_resource::<xds_cluster::Cluster>(CLUSTER_TYPE, resource)?;
            if cluster.name.is_empty() {
                continue;
            }
            let eds_service_name = cluster
                .eds_cluster_config
                .as_ref()
                .filter(|eds| !eds.service_name.is_empty())
                .map(|eds| eds.service_name.clone())
                .unwrap_or_else(|| cluster.name.clone());

            if let Some(load_assignment) = cluster.load_assignment.as_ref() {
                self.endpoints.insert(
                    eds_service_name.clone(),
                    endpoints_from_assignment(load_assignment),
                );
            }

            self.clusters.insert(
                cluster.name.clone(),
                ClusterSnapshot {
                    tls: upstream_tls_from_cluster(&cluster),
                    name: cluster.name,
                    eds_service_name,
                },
            );
        }

        Ok(DiscoveryUpdates {
            eds_names: self.eds_names(),
            ..DiscoveryUpdates::default()
        })
    }

    fn apply_endpoints(
        &mut self,
        resources: &[prost_types::Any],
    ) -> Result<DiscoveryUpdates, XdsError> {
        let requested = self.subscription(ENDPOINT_TYPE);
        prune_requested(&mut self.endpoints, &requested);
        for resource in resources {
            let assignment =
                decode_resource::<xds_endpoint::ClusterLoadAssignment>(ENDPOINT_TYPE, resource)?;
            if assignment.cluster_name.is_empty() {
                continue;
            }
            self.endpoints.insert(
                assignment.cluster_name.clone(),
                endpoints_from_assignment(&assignment),
            );
        }
        Ok(DiscoveryUpdates::default())
    }

    fn runtime_config(&self, version: &str) -> RuntimeConfig {
        let listeners = self
            .listeners
            .values()
            .map(|snapshot| {
                let mut listener = snapshot.listener.clone();
                listener.virtual_hosts = snapshot.inline_virtual_hosts.clone();
                for route_name in &snapshot.route_names {
                    if let Some(vhosts) = self.routes.get(route_name) {
                        listener.virtual_hosts.extend(vhosts.clone());
                    }
                }
                listener
            })
            .collect();

        let clusters = self
            .clusters
            .values()
            .map(|cluster| Cluster {
                name: cluster.name.clone(),
                endpoints: self
                    .endpoints
                    .get(&cluster.eds_service_name)
                    .cloned()
                    .unwrap_or_default(),
                tls: cluster.tls.clone(),
            })
            .collect();

        RuntimeConfig {
            version: if version.is_empty() {
                "ads".to_string()
            } else {
                version.to_string()
            },
            listeners,
            clusters,
            secrets: Vec::new(),
        }
    }

    fn subscription(&self, type_url: &str) -> Vec<String> {
        self.subscriptions
            .get(type_url)
            .cloned()
            .unwrap_or_default()
    }

    fn set_subscription(&mut self, type_url: &str, names: Vec<String>) -> bool {
        let names = sorted_unique(names);
        if self.subscriptions.get(type_url) == Some(&names) {
            return false;
        }
        self.subscriptions.insert(type_url.to_string(), names);
        true
    }

    fn route_names(&self) -> Vec<String> {
        sorted_unique(
            self.listeners
                .values()
                .flat_map(|listener| listener.route_names.iter().cloned()),
        )
    }

    fn cluster_names(&self) -> Vec<String> {
        sorted_unique(self.routes.values().flat_map(|vhosts| {
            vhosts.iter().flat_map(|vh| {
                vh.routes.iter().flat_map(|route| {
                    route
                        .weighted_clusters
                        .iter()
                        .map(|cluster| cluster.name.clone())
                })
            })
        }))
    }

    fn eds_names(&self) -> Vec<String> {
        sorted_unique(
            self.clusters
                .values()
                .map(|cluster| cluster.eds_service_name.clone()),
        )
    }
}

#[derive(Default)]
struct DiscoveryUpdates {
    route_names: Vec<String>,
    cluster_names: Vec<String>,
    eds_names: Vec<String>,
}

impl DiscoveryUpdates {
    fn subscriptions(self) -> Vec<(&'static str, Vec<String>)> {
        let mut out = Vec::new();
        if !self.route_names.is_empty() {
            out.push((ROUTE_TYPE, self.route_names));
        }
        if !self.cluster_names.is_empty() {
            out.push((CLUSTER_TYPE, self.cluster_names));
        }
        if !self.eds_names.is_empty() {
            out.push((ENDPOINT_TYPE, self.eds_names));
        }
        out
    }
}

#[derive(Debug, Clone)]
struct ListenerSnapshot {
    listener: Listener,
    route_names: Vec<String>,
    inline_virtual_hosts: Vec<VirtualHost>,
}

#[derive(Debug, Clone)]
struct ClusterSnapshot {
    name: String,
    eds_service_name: String,
    tls: Option<UpstreamTls>,
}

fn upstream_tls_from_cluster(cluster: &xds_cluster::Cluster) -> Option<UpstreamTls> {
    let typed_config = match cluster.transport_socket.as_ref()?.config_type.as_ref()? {
        xds_core::transport_socket::ConfigType::TypedConfig(any) => any,
    };
    if !typed_config
        .type_url
        .ends_with("extensions.transport_sockets.tls.v1.UpstreamTlsContext")
    {
        return None;
    }
    let tls = xds_tls::UpstreamTlsContext::decode(typed_config.value.as_slice()).ok()?;
    let common = tls.common_tls_context.as_ref();
    Some(UpstreamTls {
        sni: first_non_empty(tls.sni, cluster_authority(&cluster.name)),
        certificate_provider: common.and_then(certificate_provider_name),
        validation_provider: common.and_then(validation_provider_name),
        alpn_protocols: common
            .map(|common| common.alpn_protocols.clone())
            .unwrap_or_default(),
    })
}

fn certificate_provider_name(common: &xds_tls::CommonTlsContext) -> Option<String> {
    common
        .tls_certificate_certificate_provider_instance
        .as_ref()
        .and_then(instance_name)
}

fn validation_provider_name(common: &xds_tls::CommonTlsContext) -> Option<String> {
    let combined = match common.validation_context_type.as_ref()? {
        xds_tls::common_tls_context::ValidationContextType::CombinedValidationContext(combined) => {
            combined
        }
    };
    combined
        .validation_context_certificate_provider_instance
        .as_ref()
        .and_then(instance_name)
}

fn instance_name(
    instance: &xds_tls::common_tls_context::CertificateProviderInstance,
) -> Option<String> {
    if instance.instance_name.is_empty() {
        None
    } else {
        Some(instance.instance_name.clone())
    }
}

fn cluster_authority(name: &str) -> Option<String> {
    name.split('|')
        .nth(3)
        .filter(|authority| !authority.is_empty())
        .map(ToString::to_string)
}

fn first_non_empty(value: String, fallback: Option<String>) -> Option<String> {
    if value.is_empty() {
        fallback
    } else {
        Some(value)
    }
}

fn listener_snapshot(listener: xds_listener::Listener) -> Result<ListenerSnapshot, XdsError> {
    let port = listener_port(&listener).unwrap_or(80);
    let mut route_names = Vec::new();
    let mut inline_virtual_hosts = Vec::new();

    for hcm in http_connection_managers(&listener)? {
        match hcm.route_specifier {
            Some(xds_hcm::http_connection_manager::RouteSpecifier::Rds(rds)) => {
                if !rds.route_config_name.is_empty() {
                    route_names.push(rds.route_config_name);
                }
            }
            Some(xds_hcm::http_connection_manager::RouteSpecifier::RouteConfig(route_config)) => {
                inline_virtual_hosts.extend(convert_virtual_hosts(&route_config.virtual_hosts));
            }
            None => {}
        }
    }

    Ok(ListenerSnapshot {
        listener: Listener {
            name: listener.name,
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
            protocol: if port == 443 {
                ListenerProtocol::Https
            } else {
                ListenerProtocol::Http
            },
            virtual_hosts: Vec::new(),
            tls_secret: None,
        },
        route_names: sorted_unique(route_names),
        inline_virtual_hosts,
    })
}

fn http_connection_managers(
    listener: &xds_listener::Listener,
) -> Result<Vec<xds_hcm::HttpConnectionManager>, XdsError> {
    let mut managers = Vec::new();

    if let Some(api_listener) = listener.api_listener.as_ref() {
        if let Some(any) = api_listener.api_listener.as_ref() {
            managers.push(decode_hcm(any)?);
        }
    }

    for chain in &listener.filter_chains {
        for filter in &chain.filters {
            let Some(xds_listener::filter::ConfigType::TypedConfig(any)) =
                filter.config_type.as_ref()
            else {
                continue;
            };
            if is_http_connection_manager(&filter.name, any) {
                managers.push(decode_hcm(any)?);
            }
        }
    }

    Ok(managers)
}

fn is_http_connection_manager(name: &str, any: &prost_types::Any) -> bool {
    name.contains("http_connection_manager")
        || any.type_url.ends_with(
            "extensions.filters.network.http_connection_manager.v1.HttpConnectionManager",
        )
}

fn decode_hcm(any: &prost_types::Any) -> Result<xds_hcm::HttpConnectionManager, XdsError> {
    decode_resource("type.googleapis.com/extensions.filters.network.http_connection_manager.v1.HttpConnectionManager", any)
}

fn convert_virtual_hosts(vhosts: &[xds_route::VirtualHost]) -> Vec<VirtualHost> {
    vhosts
        .iter()
        .map(|vh| VirtualHost {
            name: vh.name.clone(),
            domains: vh.domains.clone(),
            routes: vh.routes.iter().filter_map(convert_route).collect(),
        })
        .collect()
}

fn convert_route(route: &xds_route::Route) -> Option<Route> {
    let weighted_clusters = match route.action.as_ref()? {
        xds_route::route::Action::Route(action) => convert_route_action(action),
        xds_route::route::Action::NonForwardingAction(_) => Vec::new(),
    };
    if weighted_clusters.is_empty() {
        return None;
    }

    let matches = match route.r#match.as_ref() {
        Some(route_match) => vec![convert_route_match(route_match)?],
        None => Vec::new(),
    };

    Some(Route {
        name: route.name.clone(),
        matches,
        weighted_clusters,
    })
}

fn convert_route_action(action: &xds_route::RouteAction) -> Vec<WeightedCluster> {
    match action.cluster_specifier.as_ref() {
        Some(xds_route::route_action::ClusterSpecifier::Cluster(name)) if !name.is_empty() => {
            vec![WeightedCluster {
                name: name.clone(),
                weight: 100,
            }]
        }
        Some(xds_route::route_action::ClusterSpecifier::WeightedClusters(weighted)) => weighted
            .clusters
            .iter()
            .filter(|cluster| !cluster.name.is_empty())
            .map(|cluster| WeightedCluster {
                name: cluster.name.clone(),
                weight: cluster.weight.unwrap_or(1),
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn convert_route_match(route_match: &xds_route::RouteMatch) -> Option<RouteMatch> {
    let path = match route_match.path_specifier.as_ref() {
        Some(xds_route::route_match::PathSpecifier::Prefix(prefix)) => {
            PathMatch::Prefix(prefix.clone())
        }
        Some(xds_route::route_match::PathSpecifier::Path(path)) => PathMatch::Exact(path.clone()),
        Some(xds_route::route_match::PathSpecifier::SafeRegex(_)) => return None,
        None => PathMatch::Prefix("/".to_string()),
    };

    let mut headers = Vec::new();
    for header in &route_match.headers {
        match header.header_match_specifier.as_ref() {
            Some(xds_route::header_matcher::HeaderMatchSpecifier::ExactMatch(value)) => {
                headers.push(HeaderMatch {
                    name: header.name.clone(),
                    value: value.clone(),
                });
            }
            Some(xds_route::header_matcher::HeaderMatchSpecifier::SafeRegexMatch(_)) => {
                return None;
            }
            None => {}
        }
    }

    Some(RouteMatch { path, headers })
}

fn endpoints_from_assignment(
    assignment: &xds_endpoint::ClusterLoadAssignment,
) -> Vec<RuntimeEndpoint> {
    let mut endpoints = Vec::new();
    for locality in &assignment.endpoints {
        for lb_endpoint in &locality.lb_endpoints {
            let Some(xds_endpoint::lb_endpoint::HostIdentifier::Endpoint(endpoint)) =
                lb_endpoint.host_identifier.as_ref()
            else {
                continue;
            };
            let Some((address, port)) = socket_address(endpoint.address.as_ref()) else {
                continue;
            };
            endpoints.push(RuntimeEndpoint {
                address,
                port,
                healthy: endpoint_is_healthy(lb_endpoint.health_status),
                node_name: None,
            });
        }
    }
    endpoints.sort_by(|a, b| a.address.cmp(&b.address).then_with(|| a.port.cmp(&b.port)));
    endpoints
}

fn endpoint_is_healthy(status: i32) -> bool {
    !matches!(
        xds_core::HealthStatus::try_from(status).unwrap_or(xds_core::HealthStatus::Unknown),
        xds_core::HealthStatus::Unhealthy
            | xds_core::HealthStatus::Draining
            | xds_core::HealthStatus::Timeout
    )
}

fn listener_port(listener: &xds_listener::Listener) -> Option<u16> {
    socket_address(listener.address.as_ref())
        .map(|(_, port)| port)
        .or_else(|| {
            listener
                .name
                .rsplit_once(':')
                .and_then(|(_, port)| port.parse::<u16>().ok())
        })
}

fn socket_address(address: Option<&xds_core::Address>) -> Option<(String, u16)> {
    let Some(xds_core::address::Address::SocketAddress(socket)) =
        address.and_then(|address| address.address.as_ref())
    else {
        return None;
    };
    let Some(xds_core::socket_address::PortSpecifier::PortValue(port)) = socket.port_specifier
    else {
        return None;
    };
    Some((socket.address.clone(), u16::try_from(port).ok()?))
}

fn decode_resource<T: Message + Default>(
    type_url: &str,
    resource: &prost_types::Any,
) -> Result<T, XdsError> {
    T::decode(resource.value.as_slice()).map_err(|source| XdsError::Decode {
        type_url: type_url.to_string(),
        source,
    })
}

fn prune_requested<T>(resources: &mut BTreeMap<String, T>, requested: &[String]) {
    if requested.is_empty() {
        resources.clear();
    } else {
        for name in requested {
            resources.remove(name);
        }
    }
}

fn sorted_unique(names: impl IntoIterator<Item = String>) -> Vec<String> {
    names
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::core::v1::{address, socket_address, Address, SocketAddress};
    use prost_types::Any;

    #[test]
    fn identity_metadata_selects_dubbod_grpc_generator() {
        let identity = RouterIdentity {
            pod_name: "dxgate-abc".into(),
            namespace: "app".into(),
            pod_ip: "10.0.0.10".into(),
            node_name: Some("node-a".into()),
            cluster_id: "Kubernetes".into(),
            dns_domain: "svc.cluster.local".into(),
        };

        assert_eq!(identity.metadata().generator, "grpc");
    }

    #[test]
    fn ads_state_builds_runtime_config_from_lds_rds_cds_and_eds() {
        let route_name = "outbound|80||orders.app.svc.cluster.local";
        let cluster_name = "outbound|8080||orders.app.svc.cluster.local";
        let listener = xds_listener::Listener {
            name: "dxgate.app.svc.cluster.local:80".into(),
            address: Some(socket("10.96.0.10", 80)),
            api_listener: Some(xds_listener::ApiListener {
                api_listener: Some(any(
                    "type.googleapis.com/extensions.filters.network.http_connection_manager.v1.HttpConnectionManager",
                    xds_hcm::HttpConnectionManager {
                        route_specifier: Some(
                            xds_hcm::http_connection_manager::RouteSpecifier::Rds(xds_hcm::Rds {
                                route_config_name: route_name.into(),
                                config_source: None,
                            }),
                        ),
                        ..xds_hcm::HttpConnectionManager::default()
                    },
                )),
            }),
            ..xds_listener::Listener::default()
        };
        let route = xds_route::RouteConfiguration {
            name: route_name.into(),
            virtual_hosts: vec![xds_route::VirtualHost {
                name: "orders".into(),
                domains: vec!["orders.example.com".into()],
                routes: vec![xds_route::Route {
                    name: "orders-default".into(),
                    r#match: Some(xds_route::RouteMatch {
                        path_specifier: Some(xds_route::route_match::PathSpecifier::Prefix(
                            "/".into(),
                        )),
                        headers: Vec::new(),
                    }),
                    action: Some(xds_route::route::Action::Route(xds_route::RouteAction {
                        cluster_specifier: Some(
                            xds_route::route_action::ClusterSpecifier::Cluster(cluster_name.into()),
                        ),
                    })),
                }],
            }],
        };
        let cluster = xds_cluster::Cluster {
            name: cluster_name.into(),
            eds_cluster_config: Some(xds_cluster::cluster::EdsClusterConfig {
                service_name: cluster_name.into(),
                eds_config: None,
            }),
            transport_socket: Some(xds_core::TransportSocket {
                name: "envoy.transport_sockets.tls".into(),
                config_type: Some(xds_core::transport_socket::ConfigType::TypedConfig(any(
                    "type.googleapis.com/extensions.transport_sockets.tls.v1.UpstreamTlsContext",
                    xds_tls::UpstreamTlsContext {
                        sni: "orders.app.svc.cluster.local".into(),
                        common_tls_context: Some(xds_tls::CommonTlsContext {
                            tls_certificate_certificate_provider_instance: Some(
                                xds_tls::common_tls_context::CertificateProviderInstance {
                                    instance_name: "workload".into(),
                                    certificate_name: "default".into(),
                                },
                            ),
                            alpn_protocols: vec!["h2".into()],
                            validation_context_type: Some(
                                xds_tls::common_tls_context::ValidationContextType::CombinedValidationContext(
                                    xds_tls::common_tls_context::CombinedCertificateValidationContext {
                                        validation_context_certificate_provider_instance: Some(
                                            xds_tls::common_tls_context::CertificateProviderInstance {
                                                instance_name: "roots".into(),
                                                certificate_name: "ROOTCA".into(),
                                            },
                                        ),
                                        default_validation_context: None,
                                    },
                                ),
                            ),
                        }),
                    },
                ))),
            }),
            ..xds_cluster::Cluster::default()
        };
        let assignment = xds_endpoint::ClusterLoadAssignment {
            cluster_name: cluster_name.into(),
            endpoints: vec![xds_endpoint::LocalityLbEndpoints {
                lb_endpoints: vec![xds_endpoint::LbEndpoint {
                    host_identifier: Some(xds_endpoint::lb_endpoint::HostIdentifier::Endpoint(
                        xds_endpoint::Endpoint {
                            address: Some(socket("10.244.0.20", 8080)),
                        },
                    )),
                    health_status: xds_core::HealthStatus::Healthy as i32,
                    ..xds_endpoint::LbEndpoint::default()
                }],
                ..xds_endpoint::LocalityLbEndpoints::default()
            }],
        };

        let mut state = AdsState::default();
        state.set_subscription(
            LISTENER_TYPE,
            vec!["dxgate.app.svc.cluster.local:80".into()],
        );
        let updates = state
            .apply_response(&response(LISTENER_TYPE, vec![any(LISTENER_TYPE, listener)]))
            .unwrap();
        assert_eq!(updates.route_names, [route_name]);
        state.set_subscription(ROUTE_TYPE, updates.route_names);

        let updates = state
            .apply_response(&response(ROUTE_TYPE, vec![any(ROUTE_TYPE, route)]))
            .unwrap();
        assert_eq!(updates.cluster_names, [cluster_name]);
        state.set_subscription(CLUSTER_TYPE, updates.cluster_names);

        let updates = state
            .apply_response(&response(CLUSTER_TYPE, vec![any(CLUSTER_TYPE, cluster)]))
            .unwrap();
        assert_eq!(updates.eds_names, [cluster_name]);
        state.set_subscription(ENDPOINT_TYPE, updates.eds_names);

        state
            .apply_response(&response(
                ENDPOINT_TYPE,
                vec![any(ENDPOINT_TYPE, assignment)],
            ))
            .unwrap();

        let cfg = state.runtime_config("v1");
        cfg.validate().unwrap();
        assert_eq!(cfg.listeners[0].bind, "0.0.0.0:80".parse().unwrap());
        assert_eq!(
            cfg.listeners[0].virtual_hosts[0].domains,
            ["orders.example.com"]
        );
        assert_eq!(cfg.clusters[0].endpoints[0].address, "10.244.0.20");
        assert_eq!(
            cfg.clusters[0]
                .tls
                .as_ref()
                .and_then(|tls| tls.sni.as_deref()),
            Some("orders.app.svc.cluster.local")
        );
        let tls = cfg.clusters[0].tls.as_ref().unwrap();
        assert_eq!(tls.certificate_provider.as_deref(), Some("workload"));
        assert_eq!(tls.validation_provider.as_deref(), Some("roots"));
        assert_eq!(tls.alpn_protocols, ["h2"]);
    }

    fn response(type_url: &str, resources: Vec<Any>) -> DiscoveryResponse {
        DiscoveryResponse {
            version_info: "v1".into(),
            resources,
            canary: false,
            type_url: type_url.into(),
            nonce: "nonce".into(),
            control_plane: None,
        }
    }

    fn any<T: Message>(type_url: &str, message: T) -> Any {
        Any {
            type_url: type_url.into(),
            value: message.encode_to_vec(),
        }
    }

    fn socket(address_value: &str, port: u32) -> Address {
        Address {
            address: Some(address::Address::SocketAddress(SocketAddress {
                address: address_value.into(),
                port_specifier: Some(socket_address::PortSpecifier::PortValue(port)),
            })),
        }
    }
}
