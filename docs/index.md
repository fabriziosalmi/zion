---
layout: home
hero:
  name: Zion
  text: Edge Gateway
  tagline: TLS reverse proxy with built-in WAF. Rust, single binary, TOML config.
  image:
    src: /logo.svg
    alt: Zion Edge Gateway
  actions:
    - theme: brand
      text: Get Started
      link: /guide/quickstart
    - theme: alt
      text: Benchmarks
      link: /benchmarks/

features:
  - title: WAF (Aho-Corasick)
    details: 70+ injection patterns scanned in a single O(N) pass. No regex, no backtracking. See benchmarks for measured throughput with WAF enabled.
  - title: In-Memory Cache
    details: Two-level cache (thread-local L1 + shared L2 DashMap). Measured 88k–216k req/s on Apple M4 depending on payload. See benchmarks/bench-native.sh.
  - title: TLS Hot-Reload
    details: Certificate reload via ArcSwap pointer swap. In-flight connections keep old cert, new connections get new cert. No process restart.
  - title: Observability
    details: Prometheus /metrics endpoint, /healthz, /readyz health checks, structured logging, X-Request-ID propagation. No sidecar.
  - title: Protocol Support
    details: HTTP/1.1, HTTP/2, WebSocket proxy, SSE streaming, CORS with pre-flight OPTIONS.
  - title: Security Defaults
    details: HSTS, rate limiting, method whitelist, URI length limit (8192 bytes), header count limit (64). Configurable per-route.
---
