# ADR-0011: `zion import` — nginx config migration, honesty over completeness

- **Status**: accepted
- **Date**: 2026-07-06
- **Deciders**: fabriziosalmi
- **Tags**: cli, migration, nginx, config, adoption, supply-chain

## Context

The biggest barrier to adopting any proxy is the fleet of nginx configs an
operator already runs; ADR-0010 (`hosts` on `RouteConfig`) made nginx
`server_name` expressible for the first time, unblocking a converter. Zion has
no struct→TOML serializer — every config struct derives `Deserialize` only,
with `deny_unknown_fields` everywhere — and the house emit path (`zion
suggest`) is a string template gated by `config::parse_schema` (issue #133:
never emit what the parser rejects). Constraints: the supply-chain posture
(cargo-vet exemptions, cargo-deny allowlist) makes every new dependency
expensive; ungated code must hold the MSRV 1.82 core floor (ADR-0007); and
nginx semantics Zion deliberately lacks (static file serving, path rewriting,
regex locations) must never be silently mistranslated.

## Decision

We added `zion import nginx <conf>` as an always-available subcommand — ungated
and dependency-free, following the `suggest` precedent — built as four stages:
(1) a hand-rolled tolerant nginx parser (lexer modeled on nginx
`ngx_conf_read_token` semantics as specified by nginxinc/crossplane: no
directive whitelist, order- and line-preserving, `include` resolution with
cycle/depth guards, std-only, ~700 LOC); (2) a proxy-oriented intermediate
model (servers, listens, server_names, locations, upstream pools, TLS); (3) a
mapper that converts the reverse-proxy subset per the normative table below,
recording a finding for every directive it touches; (4) a hand-rolled TOML
emitter producing `zion.toml` with inline `# UNSUPPORTED:` annotations, gated
exactly like `suggest`: the emitted TOML must round-trip through
`config::parse_schema` plus reference-integrity checks before it is ever
printed — a failure is an internal bug and nothing is emitted. The governing
principle is **honesty over completeness**: a directive without a faithful
Zion equivalent becomes a loud finding in the conversion report, never a
best-effort guess; a converter trustworthy at 80% beats one silently wrong at
95%.

## Consequences

- **Positive**: "rewrite everything" becomes "one command + review" — the
  fastest on-ramp Zion can offer, and the wedge for migration engagements.
  Zero new dependencies: no cargo-vet exemptions, no license review, no new
  clippy flavor, MSRV 1.82 holds. The #133 guarantee extends to imported
  configs; the golden corpus (`tests/fixtures/import/nginx/`) is the
  executable spec and regression net.
- **Negative**: we own ~700 lines of parsing code (bounded: the nginx config
  grammar is tiny and frozen; crossplane is the reference oracle). The mapping
  table is a maintenance surface that must track both nginx idioms and Zion's
  schema. `import` ships in the default binary, so its code is constrained to
  MSRV 1.82.
- **Neutral / risks**:
  - **Unrepresentable semantics are the product's edge, stated as such**: no
    static serving, no path rewriting (`proxy_pass` URI part, `rewrite`), no
    per-location rate limits, no LB strategies, no response compression, no
    inbound-`Host` preservation. Each has a fixed policy in the table below;
    the report is the safety valve.
  - **Parser hard cases are bounded**: `*_by_lua_block` bodies (raw
    balanced-brace scan, quote-aware; the block itself is unsupported) and
    unquoted `{` in regex location args (nginx itself errors there — parity).
    Anti-panic property tests (house `mod proptests` style) pin tolerance:
    arbitrary input may fail with an error, never crash.
  - `parse_schema` alone does not check reference integrity (route→upstream,
    `hosts` validity); those live in `validate_config`, which also demands
    cert files exist on disk. We factor the filesystem-free checks out as
    `validate_semantics` (behavior-preserving split of `validate_config`) so
    import can run schema + semantics without touching disk.

## Mapping contract (normative)

Statuses: **convert** (faithful), **partial** (converted with a semantic
delta, annotated), **auto** (Zion does it built-in; directive dropped with an
info finding), **unsupported** (loud finding, inline `# UNSUPPORTED:`
annotation, no emission).

| nginx | Status | Zion mapping / policy |
|---|---|---|
| `server_name a.com b.com` | convert | `hosts = ["a.com","b.com"]` on that server's routes, lowercased (ADR-0010) |
| `server_name *.example.com` | convert | leading-label wildcard, allowed as-is |
| `server_name .example.com` | convert | expands to `["example.com", "*.example.com"]` |
| `server_name _` / empty / `default_server` | convert | hostless routes (Zion shared layer = default vhost) |
| `server_name ~regex` / `www.example.*` | unsupported | if a server has **no** valid name left, its routes are **skipped** (emitting them hostless would hijack the shared layer) |
| `listen 80` / `listen 443 ssl` | convert | `server.listen_http` / `listen_https`; one listener each — first port seen wins, differing ports per-server are unsupported findings |
| plain-HTTP vhost (no `ssl`) | partial | Zion always terminates TLS (`:80` only redirects); placeholder cert paths are synthesized à la `suggest` and the behavior change is reported |
| `location /p` (prefix) | partial | `path = "/p/{*rest}"` (+ Zion's auto bare-prefix alias). Divergence noted: nginx string-prefix also matches `/pfoo` |
| `location = /exact` | convert | `path = "/exact"` |
| `location ~ regex` / `~*` / `^~` | unsupported / partial | regex locations skipped with finding; `^~` treated as plain prefix (note) |
| `proxy_pass http://up;` (no URI part) | convert | route `upstream` + `[upstream.<name>]`; nginx forwards the path unchanged — exactly Zion's behavior |
| `proxy_pass http://up/;` or `/prefix/` (URI part) | unsupported* | Zion never rewrites the forwarded path and drops any upstream-URL path. *Exception: replacing `/` with `/` under `location /` is a no-op → convert |
| `proxy_pass` with variables (`$target`) | unsupported | dynamic upstreams don't exist |
| `upstream up { server a; server b; }` | convert | `[upstream.up] urls = [...]` |
| `least_conn` / `ip_hash` / `weight=` / `backup` / `max_fails` | unsupported | Zion's LB is fixed: health-gated lowest-EWMA-latency; health checks automatic |
| `keepalive 32` (upstream) | convert | `upstream.<n>.keepalive = 32` |
| `proxy_connect_timeout 75s` | convert | `connect_timeout_ms = 75000` |
| `proxy_read_timeout` / `send_timeout` / `client_body_timeout` | unsupported | no schema target |
| `proxy_set_header X-Real-IP / X-Forwarded-For / X-Forwarded-Proto ...` | auto | Zion sets all three unconditionally (`apply_forwarding_hygiene`) |
| `proxy_set_header Host $host` | unsupported | Zion strips inbound `Host` and re-derives from the upstream authority; original survives only as `X-Forwarded-Host` — behavior delta reported |
| `proxy_set_header <other>` / `add_header <other>` | unsupported | no generic header-manipulation target |
| `add_header Content-Security-Policy ...` | convert | `route.csp` |
| `add_header Strict-Transport-Security ...` | auto | Zion injects HSTS (+XCTO, XFO, Referrer-Policy, Permissions-Policy) on every response; differing values cannot be honored → finding |
| `set_real_ip_from` / `real_ip_header` | convert | `server.trusted_proxies` CIDRs / `xff_mode` (non-XFF headers like `CF-Connecting-IP`: unsupported finding) |
| `client_max_body_size 64m` | partial | `[waf_profile.imported]` `max_body_mb = 64` + attach to routes; footgun stated: the cap is enforced only via the WAF path, which adds inspection the nginx config didn't have (`waf_shadow = true` is the migration-safe stance) |
| `limit_req` / `limit_conn` | partial | exactly one distinct policy in the file → `server.rate_limit_rps`/`window` / `max_connections_per_ip` with a scope-widening note (global in Zion, per-location in nginx); multiple distinct policies → unsupported findings, none applied |
| `return 301 https://$host$request_uri` (port-80 server) | auto | Zion's `:80` handler is exactly this; the redirect server is dropped |
| other `return` / `rewrite` / `if` / `map` / `set` | unsupported | no rewrite engine by design |
| `ssl_certificate` / `_key` (per server) | convert | `[[tls.sni]]` per host; first server's pair doubles as the default `[tls]` cert |
| `ssl_protocols TLSv1.2 ...` | convert | `tls.min_version = "1.2"`; 1.3-only is Zion's default |
| `ssl_ciphers` / `ssl_prefer_server_ciphers` | unsupported | rustls owns cipher policy |
| `proxy_pass https://...` | convert | https upstream URL (`proxy_ssl_verify off`: unsupported finding) |
| websocket idiom (`proxy_set_header Upgrade $http_upgrade` + `Connection`) | convert | `mode = "websocket"`; the two headers are then auto |
| `proxy_buffering off` | unsupported | finding suggests `mode = "sse_stream"` for SSE endpoints; no blind mapping |
| `root` / `alias` / `try_files` / `index` / `error_page` / `expires` | unsupported | Zion serves no files from disk (`mode = "static_cache"` is upstream-response caching — the near-name is called out in the finding) |
| `fastcgi_pass` / `uwsgi_pass` / `scgi_pass` | unsupported | Zion is a proxy, not an app server |
| `gzip` / `brotli` | unsupported | Zion never compresses; backend should |
| `auth_basic` | unsupported | Zion auth profiles are JWT/OIDC |
| `access_log` / `log_format` / `deny` / `allow` / unknown directives | unsupported | tolerant parse, loud finding — never a crash |

**Report contract**: every input directive lands in exactly one finding bucket
(convert / partial / auto / unsupported); the report is printed to stderr and
optionally `--report <file>`; `--strict` exits non-zero if any partial or
unsupported finding exists. Exit codes: 0 converted, 1 fatal (unreadable
input, unparseable config, internal self-validation failure — nothing
emitted), 2 strict-mode findings.

## Alternatives considered

- **`nginx-config` crate (tailhook)** — dead since 2018; its AST is an
  exhaustive 73-variant enum with no unknown-directive fallback, so it errors
  on any real-world config using unlisted directives; depends on the
  deprecated `failure` crate that cargo-deny's advisory gate rejects. Lost on
  all three axes (tolerance, maintenance, supply-chain). Its fork
  `clia-nginx-config` inherits everything.
- **`nginx-lint-parser`** — the only alive, tolerant, lossless option (rowan
  CST, accepts any directive). Lost: 0.x with near-weekly breaking releases,
  single maintainer, ~4–6 new cargo-vet exemptions, edition 2024 (≥1.85)
  breaks the ungated-MSRV-1.82 choice. Named fallback if owning parser code
  proves unwanted.
- **tree-sitter-nginx** — drags the tree-sitter C runtime via a `cc` build
  dependency (worst case for cargo-vet) and is an editor-grade grammar, not
  nginx-faithful lexing. Lost.
- **Shelling out to python crossplane** — a runtime Python dependency in an
  operator CLI is unacceptable; but we adopt crossplane's lexer semantics as
  the reference and its Apache-2.0 test corpus as a differential oracle.
- **serde `Serialize` + toml serializer for emission** — would add derives
  across every config struct and still couldn't produce inline
  `# UNSUPPORTED:` annotations; the house precedent (`suggest`) is
  template-emit + `parse_schema` gate. Lost.
- **Feature-gating `import`** (tui-style pattern) — lost: dependency-free
  deterministic systems code is exactly what `suggest` ships ungated; a gate
  would buy no binary leanness and cost a 13th clippy matrix flavor.
- **Caddyfile front-end first** — Caddy's grammar is simpler and its users
  migration-friendlier, but the nginx installed base is the actual inertia
  being attacked. Caddy remains the planned second front-end on the same IR.

## References

- Issue #133 (`suggest` self-validation guarantee); `src/suggest.rs` (template
  + `parse_schema` gate, "always available" precedent)
- `src/config.rs` — `parse_schema`, `validate_config` (to be split:
  `validate_semantics` + filesystem checks), `RouteConfig.hosts`,
  `validate_host_entry`
- `src/proxy.rs` — `apply_forwarding_hygiene` (Host strip, XFF/X-Real-IP/XFP
  injection); `src/security.rs` — `inject_security_headers`
- ADR-0007 (two-tier MSRV), ADR-0010 (host-based L7 routing)
- nginxinc/crossplane (reference lexer semantics + JSON schema + corpus,
  Apache-2.0); nginx `ngx_conf_read_token`
- `tests/fixtures/import/nginx/` — golden corpus (the executable spec)
