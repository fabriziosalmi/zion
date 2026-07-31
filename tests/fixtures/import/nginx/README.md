# `zion import nginx` — golden corpus

Ten realistic nginx configs that together exercise every row of the ADR-0011
mapping contract (plus the `mode = "static"` mapping of ADR-0016). This corpus
is the executable spec for the importer: the
corpus test converts every file and asserts (a) the output passes
`config::parse_schema` + `validate_semantics`, (b) the findings match the
expectations below. Add a fixture *before* teaching the mapper a new
directive.

Expected outcome per fixture (statuses per ADR-0011: convert / partial /
auto / unsupported):

| Fixture | Scenario | Must convert | Must flag |
|---|---|---|---|
| `01-nextjs.conf` | Next.js behind proxy, websocket HMR | `server_name` → hosts; `proxy_pass` (no URI part); Upgrade idiom → `mode = "websocket"` | XFF/X-Real-IP/XFP set_headers → auto; `Host $host` → unsupported; `proxy_cache_bypass` → unsupported |
| `02-wordpress.conf` | Container WP, uploads, timeouts | hosts (2 names); `client_max_body_size 64m` → waf_profile partial; `proxy_connect_timeout` → `connect_timeout_ms` | `proxy_read_timeout`/`proxy_buffering` → unsupported; regex dotfile-deny location → unsupported (skipped) |
| `03-api-gateway.conf` | One vhost, many locations, one limit_req zone | exact + prefix locations → distinct routes/upstreams; single `limit_req` policy → global `rate_limit_rps` partial | `add_header X-Gateway` → unsupported |
| `04-static-plus-proxy.conf` | SPA static + `/api` proxied | `location /` (inherited `root` + `try_files … /index.html`) → `mode = "static"` + `serve_dir` + `spa_fallback` (ADR-0016); `/api/` route (`proxy_pass` URI part dropped, authority-only) | `expires` → unsupported; `/assets/` (only `expires`/`access_log off`, no static signal) → skipped, served by the catch-all |
| `05-multi-vhost.conf` | 3 server blocks incl. `default_server _` | per-host routes on the same path; `_` catch-all → hostless shared route | partial: default-vhost scope widening (Zion's shared layer is also the path-miss fallback under named hosts) |
| `06-upstream-lb.conf` | upstream pool | `urls` (3 backends); `keepalive 32` → keepalive | `least_conn`/`weight`/`backup`/`proxy_next_upstream` → unsupported |
| `07-tls-termination.conf` | TLS + redirect pair | ssl cert/key → `[tls]`/`[[tls.sni]]`; `ssl_protocols TLSv1.2 …` → `min_version = "1.2"`; https upstream; port-80 `return 301 https://…` server → auto (dropped) | `ssl_ciphers`/`proxy_ssl_verify off`/HSTS `add_header` → auto/unsupported per table |
| `08-wildcard-vhost.conf` | `*.tenants` wildcard + apex | wildcard + exact hosts; shared wildcard cert via SNI | — |
| `09-behind-cdn.conf` | Origin behind CDN | `set_real_ip_from` (3 CIDRs incl. IPv6) → `trusted_proxies`; `limit_conn` → `max_connections_per_ip` partial | `real_ip_header CF-Connecting-IP` (non-XFF) → unsupported; `gzip` → unsupported |
| `10-gnarly.conf` | Hostile: map/if/rewrite/regex/vars/auth_basic/error_page/log_format | only `/okay/` converts; parser must survive everything (braces in regex args, variable proxy_pass) | everything else → unsupported findings, zero crashes, zero silent drops |

House rules: files are lowercase-numbered `NN-name.conf`; keep them realistic
(modeled on wild configs, not synthetic minimal cases); every fixture header
comment states what it exercises.
