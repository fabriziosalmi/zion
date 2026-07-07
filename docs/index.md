---
layout: home
title: Zion Edge Gateway
titleTemplate: TLS reverse proxy · WAF · RAM cache, in Rust
description: One auditable Rust binary at the edge — TLS 1.3 termination, a zero-regex WAF, and a two-level RAM cache. No sidecars, no GeoIP database, no control plane.
---

<div class="ds-home">
  <header class="ds-mast"><div class="ds-mast-in">
    <div class="ds-lead">
      <div class="ds-idx">Edge gateway · Rust</div>
      <h1>One binary at the boundary of your network.</h1>
      <p>Zion terminates <b>TLS&nbsp;1.3</b>, inspects every request with a <b>zero-regex WAF</b>, serves hot paths from a <b>two-level RAM cache</b>, and proxies the rest — one auditable executable in place of nginx, a WAF module, a cache, and a geo-tagger. Explicit knobs, not a black box.</p>
      <div class="ds-acts">
        <a class="ds-btn pri" href="/zion/guide/quickstart">Read the guide</a>
        <a class="ds-btn" href="/zion/guide/cli">zion import nginx</a>
        <a class="ds-btn" href="https://github.com/fabriziosalmi/zion">Source</a>
      </div>
    </div>
    <aside class="ds-spec">
      <div class="cap">Specification</div>
      <dl>
        <div class="ds-row"><dt>Version</dt><dd class="tnum">0.6.2</dd></div>
        <div class="ds-row"><dt>Language</dt><dd>Rust · MSRV 1.82</dd></div>
        <div class="ds-row"><dt>Binary</dt><dd class="tnum">~4 MB · static</dd></div>
        <div class="ds-row"><dt>TLS proxy</dt><dd class="tnum">108<span class="u">k</span> req/s</dd></div>
        <div class="ds-row"><dt>Cache hit</dt><dd class="tnum">222<span class="u">k</span> req/s</dd></div>
        <div class="ds-row"><dt>Runtime deps</dt><dd>none</dd></div>
        <div class="ds-row"><dt>License</dt><dd>Apache-2.0</dd></div>
      </dl>
    </aside>
  </div></header>

  <section class="ds-sec"><div class="ds-sec-in">
    <div class="ds-sec-label">
      <div class="n">§1</div>
      <h2>Capabilities</h2>
      <p>Sharp primitives, each cheap enough to leave on under load.</p>
    </div>
    <div class="ds-sec-body">
      <div class="ds-cap"><div class="t">TLS<small>termination</small></div><div class="d">rustls on aws-lc-rs with hardware AES. Multi-SNI, session tickets, 0-RTT. Certificates swap via <code>ArcSwap</code> with <b>zero dropped connections</b> on reload.</div></div>
      <div class="ds-cap"><div class="t">WAF<small>inspection</small></div><div class="d">Aho-Corasick in a single <b>O(N)</b> pass — five gates, Shannon entropy, simd-json structural limits. A shadow mode logs without blocking.</div></div>
      <div class="ds-cap"><div class="t">Cache<small>two-level</small></div><div class="d">L1 thread-local intrusive LRU + L2 sharded <code>DashMap</code>, generation coherence, request coalescing. No stale read after an update.</div></div>
      <div class="ds-cap"><div class="t">Protocol<small>1.1 / 2 / 3</small></div><div class="d">HTTP/2 upstream multiplexing, WebSocket pipe, zero-buffer SSE, HTTP/3 QUIC (feature-gated). ACME auto-HTTPS on by default in the release build.</div></div>
      <div class="ds-cap"><div class="t">Edge<small>sovereign</small></div><div class="d">Per-IP rate limit <b>and</b> concurrent-connection cap, IT/EU origin tagging with no GeoIP database, Ed25519-signed mesh reputation, an L7 tarpit.</div></div>
      <div class="ds-cap"><div class="t">Ops<small>observable</small></div><div class="d">Prometheus <code>/metrics</code>, hot config reload, a live <code>zion top</code> TUI. Cosign-signed container, CycloneDX SBOM, SLSA provenance.</div></div>
    </div>
  </div></section>

  <section class="ds-sec"><div class="ds-sec-in">
    <div class="ds-sec-label">
      <div class="n">§2</div>
      <h2>Start</h2>
      <p>From zero to a running daemon in about a minute.</p>
    </div>
    <div class="ds-sec-body">
      <div class="ds-cap"><div class="t">Install<small>quickstart</small></div><div class="d">Build the release binary, run <code>zion auto</code> for an ephemeral cert + config, and you have TLS in front of a backend. → <a href="/zion/guide/quickstart">Quick start</a></div></div>
      <div class="ds-cap"><div class="t">Migrate<small>from nginx</small></div><div class="d">Convert an existing config with <code>zion import nginx</code> — a validated <code>zion.toml</code> and an honest findings report. → <a href="/zion/guide/">Guide</a></div></div>
      <div class="ds-cap"><div class="t">Configure<small>reference</small></div><div class="d">One hot-reloaded TOML file: routes, upstreams, WAF profiles, TLS, ACME, CORS. → <a href="/zion/config/">Configuration</a></div></div>
    </div>
  </div></section>
</div>
