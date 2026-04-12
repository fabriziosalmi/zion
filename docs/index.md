---
layout: home
hero:
  name: Zion
  text: Edge Gateway
  tagline: High-performance TLS reverse proxy with built-in WAF. Written in Rust.
  actions:
    - theme: brand
      text: Get Started
      link: /guide/quickstart
    - theme: alt
      text: Benchmarks
      link: /benchmarks/

features:
  - icon: "🔒"
    title: Aerospace-Grade WAF
    details: 70+ injection patterns scanned in a single O(N) pass via Aho-Corasick. No regex. ReDoS-immune by construction.
  - icon: "⚡"
    title: Sub-Millisecond P50
    details: 140k req/s cached RAM, 46k static proxy. Pre-parsed URIs, mimalloc, thread-local L1 cache, two-level eviction. Zero allocation on the hot path.
  - icon: "🔄"
    title: Zero-Downtime TLS
    details: Certificate hot-reload via ArcSwap atomic pointer swap with generation counter. Session tickets, 0-RTT early data, thread-local SNI cache, predictive cert pre-warming.
  - icon: "📊"
    title: Built-in Observability
    details: Prometheus metrics, health endpoints, structured logging, X-Request-ID tracing. No sidecar needed.
  - icon: "🌐"
    title: Modern Protocol Support
    details: HTTP/2, WebSocket proxy, SSE streaming, CORS with pre-flight OPTIONS. Ready for Next.js, React, and real-time apps.
  - icon: "🛡️"
    title: Defense in Depth
    details: HSTS, rate limiting, method whitelist, URI length limits, header bomb prevention. All at zero measurable latency.
---
