# Zion Edge Gateway Deployments

This directory contains resources for deploying Zion.

## Helm Chart (Kubernetes)

We provide a Helm chart for deploying Zion to Kubernetes clusters. The chart configures:
- ConfigMap injection for `zion.toml`, with `[tls]` from a TLS Secret you provide
- Startup, liveness and readiness probes over HTTPS (`/healthz`, `/readyz`)
- Service configuration (TCP/UDP multiplexing for HTTPS and QUIC)
- A HorizontalPodAutoscaler (`autoscaling.enabled`, default on), a PodDisruptionBudget
  when there is more than one replica, and a 45 s termination grace period

### Installation

Zion needs a serving certificate: a `kubernetes.io/tls` Secret (for example issued by
cert-manager). The chart refuses to render without one.

```bash
kubectl create secret tls zion-tls --cert=tls.crt --key=tls.key
helm install zion deploy/helm/zion \
  --set tls.existingSecret=zion-tls \
  --set-string 'config.upstreams.app=http://app.default.svc:8000' \
  --set 'config.routes[0].path=/{*rest}' --set 'config.routes[0].upstream=app'
# or put the same in a values file: helm install zion deploy/helm/zion -f my-values.yaml
```

Every values file in `deploy/helm/zion/ci/` is rendered in CI and the resulting
`zion.toml` is checked with `zion doctor` (`scripts/check-helm-chart.sh`).

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
3. **Capabilities**: The Helm chart drops all Linux capabilities (`drop: - ALL`) and runs as `uid 65532` (the distroless nonroot user — matches the Dockerfile `USER` and `values.yaml` `runAsUser`).
4. **QUIC (HTTP/3)**: To support QUIC, configure the Load Balancer to pass UDP traffic on port 443. The Service YAML sets `protocol: UDP` for the `quic` port.
