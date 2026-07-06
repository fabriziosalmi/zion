# ADR-0010: Host-based L7 routing (virtual hosting)

- **Status**: accepted
- **Date**: 2026-07-06
- **Deciders**: fabriziosalmi
- **Tags**: routing, virtual-hosting, config, performance, security

## Context

Zion routes L7 purely by path: a single `matchit::Router<Arc<ResolvedRoute>>`
keyed on `req.uri().path()` (`config::build_router`, `dispatch.rs:491`). The
only host-awareness in the stack is at TLS — `[[tls.sni]]` selects a
*certificate* per SNI (`config::SniCert`) — but the HTTP layer is host-blind.
The `Host` header is read only to validate the HTTP→HTTPS redirect
(`main.rs:2059`) and to populate `X-Forwarded-Host` before being stripped
(`proxy.rs:174`); it never enters route selection. Consequence:
`examples/multi-site.toml` ("3 domains, 3 backends") only works because the
domains use disjoint path prefixes — two hosts serving the same path (e.g.
`/`) to different backends is impossible. This blocks Zion from being a
drop-in replacement for nginx `server_name` / Caddy site blocks / Traefik
`Host()` rules. Constraints: (1) zero cost when unused — Zion's design
invariant ("absent block ⇒ zero overhead"); (2) backward-compatible — a route
with no host binding must behave exactly as today; (3) the route lookup is
fronted by a thread-local cache keyed on `FNV(path)` only (`dispatch.rs:476`).

## Decision

We add an optional `hosts: Option<Vec<String>>` to `RouteConfig`. A route with
`hosts` set is served only for those authorities; a route without `hosts` is a
**shared route** matching every authority. The single global router is replaced
by a `HostRouter` holding: a `default` radix tree (the hostless/shared routes —
byte-for-byte today's router), a `by_host: HashMap<Box<str>, Router<…>>` of
exact-host trees, a `wildcards: Vec<(suffix, Router<…>)>` for `*.example.com`
(Phase 2), and an `active` bool. Lookup normalizes the authority (lowercase,
strip `:port` — IPv6-literal-safe — strip trailing `.`) then resolves in order:
**exact host → wildcard suffix → `default` (shared) → 404**. This is the
*hostless-as-shared-layer* fallback: host-specific routes override, common
routes (health, metrics, catch-all) live hostless and are reachable from every
host. The authority is taken from `req.uri().authority()` first (HTTP/2
`:authority`, absolute-form) then the `Host` header (HTTP/1 origin-form),
gated through the existing `security::is_valid_host`. Per-host trees are built
by reusing `build_router`'s existing alias logic (`catchall_bare_prefix`,
`trailing_slash_variant`) verbatim per host-group. When no route declares
`hosts`, `active` is `false` and the hot path short-circuits to `default.at`,
identical to today. **When `active`, the thread-local route cache key becomes
`hash(host ‖ path)`.** Both lookup sites are updated: `dispatch.rs:491` and the
ACME HTTP-01 upstream fallback at `main.rs:2043`.

## Consequences

- **Positive**: true virtual hosting — same path, different host, different
  backend. Drop-in parity with nginx/Caddy/Traefik for the common case.
  Zero measurable cost when no route declares `hosts` (`active=false`
  short-circuit). The battle-tested alias logic is reused unchanged per
  host-group, not reimplemented. Per-host isolation is a natural consequence:
  a host's tree cannot resolve another host's routes.
- **Negative**: one extra `HashMap` probe + authority normalization on the hot
  path *when active* (~10–20 ns on top of the ~5 ns cache-hit / ~30 ns radix
  path). Larger config surface and validation (per-host, not global,
  `(host, path)` de-duplication). `print_routes_table` and per-route metrics
  gain a host dimension.
- **Neutral / risks**:
  - **[LOAD-BEARING] Route-cache poisoning.** The thread-local cache is keyed
    on path only today. If left unchanged under host routing,
    `api.example.com/x` and `app.example.com/x` collide → a cache hit returns
    the wrong `ResolvedRoute` → **cross-host misrouting that can bypass a
    per-route `waf_profile` / `auth_profile` or reach an `internal_only`
    backend** (tenant confusion). The key MUST fold in the normalized host when
    `active`. This is the one non-obvious change to the hot path and is a
    security invariant, not an optimization.
  - **Host vs `:authority` divergence** (request-routing smuggling surface):
    HTTP/1 clients may send a `Host` differing from an absolute-form target;
    HTTP/2 carries `:authority`. We fix a single precedence (URI authority
    first, then `Host`) and validate before use.
  - Wildcard precedence (exact beats `*.example.com` beats bare `*`) is defined
    in the contract below; regex host matching is explicitly out of scope.
  - Hot-reload (ADR-0001, ArcSwap) swaps the whole `HostRouter` atomically —
    no partially-built host map is ever observable.

## Behaviour contract (normative)

Config: `A` = route `hosts=["api.example.com"]` → upstream `api`; `S` = route
with no `hosts` (shared) `path="/{*rest}"` → upstream `frontend`; both define
`path="/x"` where noted. Authority normalization is applied before matching.

| Request authority        | Path      | Resolves to        | Rule            |
|--------------------------|-----------|--------------------|-----------------|
| `api.example.com`        | `/x`      | `A` (`api`)        | exact host      |
| `api.example.com:8443`   | `/x`      | `A` (`api`)        | port stripped   |
| `API.example.com`        | `/x`      | `A` (`api`)        | case-folded     |
| `api.example.com.`       | `/x`      | `A` (`api`)        | trailing dot    |
| `app.example.com`        | `/x`      | `S` (`frontend`)   | shared fallback |
| `api.example.com`        | `/other`  | `S` (`frontend`)   | host miss → shared |
| *(no Host, HTTP/1.0)*    | `/x`      | `S` (`frontend`)   | hostless → shared |
| `[2001:db8::1]:443`      | `/x`      | `S` (`frontend`)   | IP literal → shared |

**Cache invariant**: for any two requests with authorities `h1 ≠ h2`
(normalized) and equal path `p`, the thread-local route cache MUST NOT let a
lookup for `(h1, p)` return the route selected for `(h2, p)` when `active`.

**Validation**: a `hosts` entry must be a bare authority — no scheme, no path,
no port; lowercased at load. `(host, path)` collisions are rejected per
host-group (the same `path` may legitimately recur across different hosts and
in the shared layer). An empty-string host is rejected.

## Alternatives considered

- **Combined `/host/path` radix key (single tree).** Encode the host as a path
  prefix and keep one `matchit` tree. Rejected: it breaks the already-subtle,
  path-shape-dependent alias logic (`catchall_bare_prefix`,
  `trailing_slash_variant` reason about `rfind('/')` and the root `/`), cannot
  cleanly express "hostless matches every host" without inserting a route under
  every known host, and a root catch-all `/{*rest}` would swallow the host
  segment.
- **nginx-strict host isolation** (a matched host block never falls back to
  shared routes). Rejected per decision: the shared layer is more ergonomic —
  health/metrics/catch-all are written once, hostless, and host routes still
  override. Strict isolation remains a one-line change (skip the `default`
  fallback once a host tree matched the host but not the path) if ever needed.
- **`[[site]]` block grouping routes under a host** (nginx `server {}` shape).
  Rejected for now: more invasive config refactor; `hosts` on `RouteConfig` is
  minimal and Traefik-rule-like. May return as ergonomic sugar that desugars to
  per-route `hosts`.
- **Do nothing — rely on SNI + path prefixes.** Rejected: impossible when two
  hosts share a path; the `examples/multi-site.toml` limitation is exactly this.

## References

- `src/config.rs` — `RouteConfig`, `build_router`, `catchall_bare_prefix`,
  `trailing_slash_variant`
- `src/dispatch.rs:461-502` — route lookup + thread-local `ROUTE_CACHE`
- `src/main.rs:2043` — ACME HTTP-01 upstream fallback (second lookup site)
- `src/security.rs:305` — `is_valid_host`
- `examples/multi-site.toml` — the host-blind "multi-site" example this fixes
- ADR-0001 (ArcSwap config + TLS hot-reload) — atomic `HostRouter` swap
- ADR-0003 (two-level cache with generation counter) — cache-key rationale
- RFC 9110 §7.2 (Host / `:authority`), nginx `server_name`, Caddy site blocks,
  Traefik `Host()` matcher, `matchit` radix router
