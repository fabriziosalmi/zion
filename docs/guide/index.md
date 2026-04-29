# What is Zion?

Zion is a TLS reverse proxy with a built-in WAF, written in Rust. One binary, one TOML config file, no runtime dependencies beyond libc.

## Features

| Feature | Implementation |
|---|---|
| TLS termination | rustls (aws-lc-rs crypto backend), TLS 1.2/1.3, ALPN, SNI |
| Routing | Radix tree via `matchit` crate |
| WAF | 5-gate pipeline: body size, content-type, Aho-Corasick (balanced or aggressive mode), Shannon entropy, simd-json structural validation |
| Caching | In-memory two-level cache: thread-local L1 + shared DashMap L2, TTL + max-entry eviction |
| WebSocket | Bidirectional proxy via HTTP Upgrade |
| SSE streaming | Dedicated proxy mode with buffer-disabling headers |
| CORS | Pre-flight OPTIONS handling, origin whitelist, configurable max-age |
| Observability | Prometheus `/metrics`, `/healthz`, `/readyz`, X-Request-ID |
| Security headers | HSTS, X-Content-Type-Options, X-Frame-Options, Permissions-Policy |
| Rate limiting | Per-IP via DashMap, configurable window and threshold |
| TLS hot-reload | Filesystem watcher (notify) + ArcSwap atomic pointer swap |
| Platform detection | Reads CPU count, RAM, AES-NI, SO_REUSEPORT, TCP_FASTOPEN at boot |

## When to Use Zion

- You need a TLS termination proxy with integrated request inspection
- You are proxying to internal HTTP services (APIs, SSR frameworks, SPAs)
- You want certificate rotation without process restarts
- You want Prometheus metrics without a sidecar or agent

## Comparison

| Capability | Zion | nginx | Envoy | Traefik |
|---|---|---|---|---|
| Language | Rust | C | C++ | Go |
| Config format | TOML | Custom DSL | YAML/xDS | YAML/labels |
| Built-in WAF | Yes (Aho-Corasick) | ModSecurity (plugin) | No | No |
| TLS hot-reload | Yes (ArcSwap) | `reload` signal | SDS/xDS | Yes |
| In-memory cache | Yes (DashMap) | proxy_cache (disk) | No | No |
| WebSocket | Yes | Yes | Yes | Yes |
| Binary size | ~5 MB | ~1.5 MB | ~40 MB | ~100 MB |
| Config complexity | 1 file | Multiple files | High | Moderate |
| Service mesh | No | No | Yes (Istio) | Yes (k8s) |

Zion is not a service mesh or API gateway with plugin ecosystems. It is a single-purpose edge proxy for TLS termination, routing, WAF, and caching.
