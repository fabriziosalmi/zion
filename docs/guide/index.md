# What is Zion?

Zion is a high-performance TLS reverse proxy with a built-in Web Application Firewall (WAF), written in Rust. One binary, one TOML config file, zero runtime dependencies.

## Key Features

| Feature | Implementation |
|---|---|
| TLS termination | rustls (aws-lc-rs), TLS 1.2/1.3, ALPN, SNI |
| Routing | Radix tree via `matchit` (~15ns lookup) |
| WAF | 6-gate pipeline, Aho-Corasick, zero regex |
| Caching | Lock-free in-memory cache (DashMap), TTL + max-entry eviction |
| WebSocket | Full bidirectional proxy with HTTP Upgrade |
| SSE streaming | Dedicated mode with no-buffer headers |
| CORS | Pre-flight OPTIONS, origin whitelist, max-age |
| Observability | Prometheus `/metrics`, `/healthz`, `/readyz`, X-Request-ID |
| Security headers | HSTS, X-Content-Type-Options, X-Frame-Options, Permissions-Policy |
| Rate limiting | Per-IP, lock-free DashMap, configurable window |
| TLS hot-reload | Filesystem watcher + ArcSwap atomic pointer swap |
| Auto-tuning | Detects CPU, RAM, AES-NI, SO_REUSEPORT, TCP_FASTOPEN |

## When to Use Zion

- You need a TLS edge proxy with integrated WAF and no external dependencies
- You want sub-millisecond P50 latency at the edge
- You are proxying to internal HTTP services (APIs, Next.js, SPAs)
- You need zero-downtime certificate rotation
- You want Prometheus metrics without a sidecar

## Comparison

| Capability | Zion | nginx | Envoy | Traefik |
|---|---|---|---|---|
| Language | Rust | C | C++ | Go |
| Config format | TOML | Custom DSL | YAML/xDS | YAML/labels |
| Built-in WAF | Yes (6-gate) | ModSecurity (plugin) | No | No |
| TLS hot-reload | Yes (ArcSwap) | `reload` signal | SDS/xDS | Yes |
| RAM cache | Yes (DashMap) | proxy_cache (disk) | No | No |
| WebSocket | Yes | Yes | Yes | Yes |
| Binary size | ~5 MB | ~1.5 MB | ~40 MB | ~100 MB |
| Config complexity | 1 file | Multiple files | High | Moderate |
| Service mesh | No | No | Yes (Istio) | Yes (k8s) |

Zion is not a service mesh or API gateway with plugin ecosystems. It is a focused edge proxy that does TLS termination, routing, WAF, and caching with minimal overhead.
