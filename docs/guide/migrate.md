# Migrating to Zion

`zion import` converts an existing reverse-proxy config — **nginx**, **Traefik**
(Docker-Compose labels), or **Caddy** — into a validated `zion.toml`. One
command turns "rewrite everything" into "review a diff."

```bash
zion import nginx   /etc/nginx/sites-enabled/app.conf -o zion.toml
zion import traefik docker-compose.yml                -o zion.toml
zion import caddy   Caddyfile                         -o zion.toml
```

## The honesty contract

The importer's governing rule is **honesty over completeness**. Every input
directive lands in exactly one of four buckets, printed as a findings report so
you know precisely what changed:

| bucket | meaning |
|---|---|
| **convert** | faithfully translated to a Zion equivalent |
| **partial** | translated, but with a stated semantic delta — read these |
| **auto** | Zion does it built-in; the directive was dropped (e.g. security headers, http→https redirect) |
| **unsupported** | no faithful equivalent — needs a human decision, never silently mistranslated |

Two guarantees hold for every front-end:

1. **Self-validation.** The emitted `zion.toml` is parsed, semantically checked,
   and its router is built *before* it is written. The importer never emits a
   config the daemon would reject.
2. **No approximate translation.** If a directive cannot map cleanly, it becomes
   a loud `unsupported`/`partial` finding rather than a plausible-but-wrong
   guess.

```
$ zion import nginx app.conf -o zion.toml
  wrote zion.toml
  zion import nginx: 14 findings — 6 convert, 2 partial, 4 auto, 2 unsupported
   line  status       directive         detail
      8  partial      server            1 plain-HTTP server(s) — Zion always terminates TLS …
     24  unsupported  proxy_set_header  Host $host — Zion re-derives Host from the upstream authority …
```

Attach the findings report to your migration PR: it *is* the record of what
changed semantically.

## nginx

Reads a `server { … }` / `location { … }` / `upstream { … }` config, including
`include` (resolved relative to the input file). Highlights:

- `server_name` → route `hosts` (exact, `*.domain`, and `.domain` apex+wildcard).
- `location` prefixes → path routes; `proxy_pass` → upstreams (deduplicated).
- The websocket `Upgrade` idiom → `mode = "websocket"`.
- `ssl_certificate`/`ssl_certificate_key` → `[tls]`; `listen 80 … return 301
  https://$host` → dropped (Zion's `:80` handler does this built-in).
- `client_max_body_size` → the imported WAF body cap (shadow mode).
- **Static serving** (`root` / `try_files` / `index` / `alias`) →
  [`mode = "static"`](#static-sites-and-spas). An SPA build dir served with
  `try_files … /index.html` next to a proxied `/api` converts in one pass.

Not translated (each a finding): `rewrite`/`handle_path` path rewriting, `if`,
`map`, per-route `deny`/`allow`, custom `error_page`, `auth_basic` (Zion auth is
JWT/OIDC), regex `location` blocks.

## Traefik

Reads **Docker-Compose** files and maps the container labels. A declared-subset
Compose reader extracts service names, labels (list *and* map form), and
`command`/`entrypoint` — refusing (with a line number) anything it cannot parse
rather than guessing.

- `traefik.enable=true` gates a service in; the rest is ignored.
- `routers.X.rule=Host(\`a\`) && PathPrefix(\`/api\`)` → `hosts` + `path`.
- `services.X.loadbalancer.server.port` → an upstream at the **compose service
  name** (`http://<service>:<port>`).
- `.tls.certresolver` + the resolver's ACME email → native
  [`[tls.acme]`](#automatic-https-acme).
- `--providers.docker=true` → the **headline finding**: Zion has no service
  discovery, so routes are frozen at import time — a service added later is not
  exposed until you re-generate the config.

### Environment variables

Compose configs are full of `${DOMAIN:-localhost}` and `${ACME_EMAIL}`. The
importer resolves them at import time — reading the `.env` next to the file and
accepting `--var KEY=VALUE`:

```bash
zion import traefik docker-compose.yml --var DOMAIN=example.com -o zion.toml
```

An unresolved variable becomes an explicit `unsupported` finding with its name
and line — never an invented value.

## Caddy

Ships its own zero-dependency Caddyfile tokenizer and parser (no Caddy
required).

- `handle /api/* { reverse_proxy api:8000 }` → path route + upstream;
  `handle {}` → the catch-all.
- `{$DOMAIN}` site addresses → `hosts`; `:80` → a hostless route.
- `tls` + email → [`[tls.acme]`](#automatic-https-acme); `auto_https off` →
  no ACME emitted.
- Most of a `header { … }` block **evaporates into `auto`** — Zion already
  injects the standard security headers (HSTS, `X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`) and strips
  `Server`. A `Content-Security-Policy` becomes the route's `csp`.
- `root` + `file_server` → [`mode = "static"`](#static-sites-and-spas).

Not translated: `handle_path` (path rewriting), `respond "…" 403` (static
responses), `encode` (Zion does not compress), named `@matcher`s.

## Automatic HTTPS (ACME)

When the source terminates TLS with a cert resolver / ACME email, the importer
emits a native `[tls.acme]` block — the imported gateway gets real, auto-renewing
Let's Encrypt certificates on first boot. Supply the contact address with
`--acme-email you@example.com` if the source config doesn't carry one.

## Static sites and SPAs

A large share of real stacks serve a built front-end *alongside* an API. Zion's
opt-in [`mode = "static"`](/config/routing) serves files from disk behind a
hardened path-safety core, so those stacks migrate to **one binary instead of a
proxy plus a static-file container**.

The importer maps a static location (nginx `root`+`try_files`, Caddy
`root`+`file_server`) to it automatically:

```toml
[[route]]
path = "/{*rest}"
hosts = ["app.example.com"]
mode = "static"
serve_dir = "/var/www/app/dist"
spa_fallback = true          # unmatched path → index.html (single-page apps)

[[route]]
path = "/api/{*rest}"
hosts = ["app.example.com"]
upstream = "backend"
```

`serve_dir` is derived exactly, not approximated: nginx `root` appends the whole
request URI while Zion strips the route prefix, so the two cancel out to the same
on-disk path.

## Verify before you cut over

Treat the import as a proposal, not a fait accompli:

1. **Read every `partial` and `unsupported` finding.** They are the semantic
   diff between the old proxy and Zion.
2. **Fill in the placeholders.** Imported configs use placeholder cert paths
   (`/etc/ssl/zion/…`) unless ACME is emitted — point them at real files.
3. **Replay a request corpus.** The [equivalence harness](https://github.com/fabriziosalmi/zion/tree/master/tests/equivalence)
   runs the legacy proxy and Zion side by side and diffs the routing decision
   request by request — every difference must be one you *declared*, not one you
   discovered in production.
4. **Run the WAF in shadow first.** Imported body caps land in shadow mode
   (`waf_shadow`): they log without blocking until you have watched real traffic.

## What does not convert (by design)

Zion refuses to guess. These are `unsupported` on purpose — the ADRs
([0011](/adr/0011-zion-import-nginx), [0012](/adr/0012-zion-import-traefik),
[0013](/adr/0013-zion-import-caddy)) record why:

- **Path rewriting** (`strip_prefix` / `handle_path` / nginx `rewrite`) — Zion
  forwards the original path unchanged.
- **Arbitrary static responses** and **custom error pages**.
- **Response compression** — a deliberate product choice.
- **Regex / conditional routing** — Zion routes on literal path segments.

If a real migration needs one of these, it is reopened as an ADR amendment, not
smuggled in as a silent approximation.
