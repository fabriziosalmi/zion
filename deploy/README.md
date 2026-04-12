# Zion Edge Gateway Deployments

This directory contains resources for deploying Zion.

## Helm Chart (Kubernetes)

We provide a Helm chart for deploying Zion to Kubernetes clusters. The chart configures:
- ConfigMap injection for `zion.toml`
- Liveness and Readiness probes (`/healthz`, `/readyz`)
- Service configuration (TCP/UDP multiplexing for HTTPS and QUIC)

### Installation

```bash
cd helm/zion
helm install zion .
# Or define configuration in a custom values file:
# helm install zion . -f my-values.yaml
```

### Exposing the Service

In the `values.yaml`:

```yaml
service:
  type: LoadBalancer
  portHttp: 80
  portHttps: 443
```

## Systemd (Bare Metal Linux)

For bare metal installations, use the `zion.service`:

```bash
sudo cp zion.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable zion
sudo systemctl start zion
```

## Deployment Notes

1. **Bare Metal**: Linux `io_uring` and `SO_REUSEPORT` bindings in `src/net.rs` can be utilized.
2. **Kubernetes**: Ensure you mount TLS certificates via Kubernetes `Secret` to `/etc/zion/certs/`, and point your `zion.toml` `cert_path` to that mount.
3. **Capabilities**: The Helm chart drops all Linux capabilities (`drop: - ALL`) and runs as `uid 1000`.
4. **QUIC (HTTP/3)**: To support QUIC, configure the Load Balancer to pass UDP traffic on port 443. The Service YAML sets `protocol: UDP` for the `quic` port.
