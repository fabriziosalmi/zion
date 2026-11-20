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
| `api.example.com:`       | `/x`      | `A` (`api`)        | empty port = default |
| `api.example.com:x`      | `/x`      | `400`, not routed  | not `host[:port]` |
| `api.example.com,x`      | `/x`      | `400`, not routed  | not a host name |
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

## Amendment (2026-11-20): one authority per request, and a hit compares the full key

Ways around both load-bearing risks above were found and closed: three around
the authority precedence, one around the cache key.

**The precedence alone did not settle Host against `:authority`.** Routing, the
route's policy and the response-cache key took the URI authority first, but the
forwarding path re-surfaced the `Host` header in `X-Forwarded-Host` (and, with
`preserve_host`, as `Host`). A client that sent both and made them differ (an
HTTP/1.1 absolute-form target plus `Host`, HTTP/2 `:authority` plus a `host`
field) had its request decided as one host and served as another: it reached an
`internal_only` vhost through an open host's route on a shared backend, and
filed an origin's answer for one host under another host's cache key. A request
that names two authorities that disagree (compared as RFC 3986 §6.2.3 has it:
host case-insensitive, an absent port equal to the scheme's default), or a target
authority with userinfo, is now refused with `400` by a pre-routing gate (after
the method whitelist) and by the same check on the `:80` handler. RFC 9113 §8.3.1
and RFC 9114 §4.3.1 make such an HTTP/2 or HTTP/3 request malformed. For
HTTP/1.1, RFC 9112 §3.2.2 would let the server answer from the target alone and
forward that authority; refusing was preferred because it keeps the authority a
client wrote in an absolute-form target from ever reaching the upstream (the
#697 corpus invariant) and leaves nothing else that reads `Host` (WAF rules, the
access log) looking at a different host than routing did. (Over HTTP/3 the `h3`
crate already resets a request stream whose `:authority` and `host` differ by a
byte, before zion sees it.)

**An authority that is not `host[:port]` was a third key.** Normalization
stripped a port only when it was non-empty and all digits, and the comparison
above read ports through `http`'s `Authority::port_u16`, which gives no port for
`a.example:x` and 443 for `a.example:+443`. So `a.example:`, `a.example:x` and
`a.example:+443` passed the comparison as `a.example` but were routed by their
whole text, which no host group or wildcard matches: the request got the shared
routes, while an upstream that cuts the host at the first `:` (nginx) or splits
host and port (Go) served `a.example`. One parser now reads every authority, for
normalization and for the gate (`security::split_authority`): a host, then
nothing or `:` and a port of ASCII digits up to 65535. An empty port is the
scheme's default (RFC 3986 §6.2.3, RFC 9110 §4.2.3) and is stripped. Anything
else (a port that is not a number or is out of range, a second `:`, a bare IPv6
literal, text after `]`, userinfo, a `Host` that is not visible ASCII) has no
key, and a request that names it, as its target or as a `Host`, is refused with
`400` by the same gate. Over HTTP/2 and HTTP/3 an `:authority` that the `http`
crate does not parse at all (a second `:` outside brackets) never reaches the
gate: `h2` and `h3` reset the stream. A `hosts` entry and a `health_host` are
checked by the same function, so one with a non-numeric port or a bare IPv6
literal, and a `hosts` entry with an empty port, is now a config error: no
request is routed by that text any more.

**A host that is not a host name was a fourth key.** The parser read the port
but took any other host text whole, and the HTTP/1.1 `Host` check let a `,`, a
`;` and a tab through. `admin.example,x` was routed by its whole text, so it got
the shared routes (or a `*.suffix` wildcard it ends with), while the upstream
was told it in `X-Forwarded-Host`, which an upstream can read as a list
(Express 5 keeps the part before the first `,`), and served `admin.example`. The
host is now a DNS-style name or IPv4 address (ASCII letters, digits, `-`, `.`,
`_`) or an IPv6 address in brackets; any other byte in it gets the `400`.

**The cache key was a hash, not the key.** The cache invariant above was
enforced by folding the host into an unseeded 64-bit FNV hash, and a hit
returned whatever the slot held. FNV is public: a colliding pair of paths can be
computed offline (the pair in the regression test came from a distinguished-point
search, about 20 seconds of wall time on six threads), and the second path of the
pair was then served under the first path's cached route. Each entry now keeps the `(host, path)` it was resolved for and a
hit compares it in full; a collision is a miss and the radix tree answers. The
key is kept in one allocation, and a key over 512 bytes is not cached, which
bounds what a flood of long distinct paths makes a worker thread hold. A seeded
hash was not added: with the full compare it would change only which pairs
share a slot, not whether a hit can be wrong.

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
