# dxgate

dxgate is the delegated gateway for Dubbo Gateway API traffic. It serves as dubbod external data-plane proxy and consumes control-plane configuration as a router xDS client.

## Bootstrap

In Kubernetes, dubbod should provide a small bootstrap file and set `DXGATE_BOOTSTRAP=/etc/dxgate/bootstrap.json`. The bootstrap file carries stable control-plane identity such as `xds_address`, `cluster_id`, and `dns_domain`; pod-specific fields still come from the Downward API environment.

After bootstrap, dxgate opens an ADS stream to dubbod, subscribes the configured LDS listener names, follows discovered RDS/CDS/EDS resources, and applies the resulting runtime config without a static route file.

If CDS returns an `UpstreamTlsContext`, dxgate opens upstream traffic with mTLS. Set `GRPC_XDS_BOOTSTRAP` to the gRPC xDS bootstrap that contains the `file_watcher` certificate provider for `cert-chain.pem`, `key.pem`, and `root-cert.pem`; otherwise the TLS-marked cluster returns `502`.

`DXGATE_STATIC_CONFIG` remains available for local development and fallback only.
