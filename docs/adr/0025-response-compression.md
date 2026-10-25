# ADR-0025: Opt-in response compression (gzip + brotli)

- **Status**: accepted
- **Date**: 2026-10-25
- **Deciders**: fabriziosalmi
- **Tags**: compression, performance, security, breach, cache

## Context

Zion has no response-compression code: it forwards whatever `Content-Encoding` the
upstream sent and serves precompressed sidecars for static files, but an edge in front
of origins that do not compress ships uncompressed text over the wire (#474). Adding
compression touches the data plane and the response-security surface: compressing a
response that mixes a secret with attacker-reflected input over TLS is the BREACH/CRIME
oracle. It also interacts with the cache (encoding-aware keys), Range-from-cache (#471),
conditional requests (ETag), and the lean-core MSRV (1.82) and strict supply-chain gates.

## Decision

Response compression is a per-route, off-by-default feature behind a `compress` Cargo
feature (in `dist`), built on pure-Rust backends (flate2/miniz_oxide for gzip, the brotli
crate for brotli; no async-compression). v1 compresses downstream at `finish_response`, the
single choke point that carries the resolved route and covers proxied, cached and static
responses; the cache therefore stores the identity body and Range-from-cache keeps slicing
identity bytes, so compression cannot corrupt a cached or ranged representation. v1 skips
206/Range, HEAD, `no-transform`, already-encoded bodies, non-text content types, bodies
below `min_bytes`, and any request whose `Accept-Encoding` does not overlap. A default-on
BREACH guard refuses to compress a response that carries `Set-Cookie` (or `Cache-Control:
private`) unless the route sets `compress.allow_cookied = true`. Compression runs under an
atomic admission counter (mirroring the `max_in_flight` bulkhead); over budget it serves the
identity body rather than shedding. On compress it sets `Content-Encoding`, adds `Vary:
Accept-Encoding`, drops `Content-Length`, and weakens a strong `ETag` to weak (`W/`).

## Consequences

- **Positive**: text responses from non-compressing origins ship smaller; opt-in and
  narrow, so no behaviour changes without config; cache and Range correctness are preserved
  by construction (identity in the cache).
- **Negative**: for cached routes, v1 compresses per hit (CPU each time) rather than once on
  store; brotli CPU is capped by level and the admission counter. Compress-on-store is a
  follow-up.
- **Neutral / risks**: BREACH is mitigated, not eliminated; the guard plus the opt-in and the
  docs warning are the posture. Four new pure-Rust crates (brotli family) enter the
  supply-chain and are vetted.

## Alternatives considered

- **Compress on store (cache the compressed variant).** Saves CPU on cached routes but makes
  Range-from-cache operate on compressed bytes and complicates identity dedup (#484). Deferred
  to a follow-up; v1 keeps the cache identity-only for correctness first.
- **async-compression + tokio layer.** Simpler streaming, but pulls more crates (bigger vet
  surface) and may raise the MSRV. Rejected for a direct flate2/brotli incremental adapter.
- **zstd.** Better ratio and speed, but the common crate is a C binding against the lean-core
  and supply-chain posture. Deferred, decided separately.
- **Always-on (no Cargo feature).** Keeping the core lean and MSRV-1.82-clean argues for gating
  behind `compress`, consistent with acme/auth/http3.

## References

- Issue #474; Tier 3 proxy-checklist item 58
- #471 (Range from cache), #484 (identity cache dedup)
- ADR-0022 (static precompressed sidecars), ADR-0007 (two-tier MSRV), ADR-0006 (feature-gated optional deps)
- BREACH (2013), CRIME (2012); RFC 9110 section 8.8.3.3 (weak ETag), section 12.5.3 (Accept-Encoding)
