# Zion Edge Gateway — TODO & Roadmap

Stato attuale: **v1.2.0** · ~6,500 LOC · 145+ test · 0 debito architetturale

## ✅ Completati (v1.0 → v1.2)

### v1.0 — Core
- [x] Audit V1: 28 finding risolti (7 bloccanti, 6 gravi, 9 critici, 6 info)
- [x] Audit V2: 9 finding risolti (4 gravi, 5 seri)
- [x] Cleanup: sysctlbyname C API, dead code removal

### v1.1 — Feature Hardening
- [x] ACME nativo via `instant-acme` (feature-gated `--features acme`)
- [x] WebSocket TLS-to-upstream via `tokio-rustls` + `webpki-roots`
- [x] CSP per-route configurabile
- [x] 0-RTT riabilitato con method gating (425 Too Early, RFC 8470)
- [x] Dockerfile con HEALTHCHECK funzionante
- [x] Integration test suite Rust (19 test `#[ignore]`)
- [x] Unit test suite: CSP, 0-RTT, WebSocket, ACME (25 test)
- [x] WAF docs: 6-gate pipeline, 70+ pattern, extension guide
- [x] Config profiles: basic, waf-strict, full-stack

### v1.2 — Enterprise
- [x] HTTP/3 (QUIC) via `quinn` + `h3` (feature-gated `--features http3`)
- [x] Observability: latency histograms (16 bucket HDR) + active connections gauge
- [x] W3C Trace Context (traceparent) propagation
- [x] TLS handshake + upstream + request duration histograms
- [x] mTLS downstream: WebPkiClientVerifier + CRL support + X-Client-Cert-DN
- [x] mTLS upstream: per-upstream client cert/key
- [x] Auth-gate JWT/OIDC (feature-gated `--features auth`)
- [x] HMAC + RSA/EC algorithm support, claim validation + forwarding
- [x] Alt-Svc header injection for HTTP/3 discovery

## 🔜 Future (v1.3+)
- [ ] JWKS URL auto-fetch + background key rotation cache
- [ ] HTTP/3 request header forwarding (full pipeline parity)
- [ ] CRL/OCSP auto-refresh for client CA
- [ ] gRPC pass-through via h2 + content-type routing
- [ ] WASM plugin system for custom request/response transforms
