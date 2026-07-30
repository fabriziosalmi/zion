# ADR-0013: `zion import caddy` — third front-end, own Caddyfile parser

- **Status**: accepted
- **Date**: 2026-07-30
- **Deciders**: fabriziosalmi
- **Tags**: cli, migration, caddy, config, adoption

## Context

ADR-0011 established the importer's neutral seam — a source-agnostic `ZionDoc`
plus a gated emitter — and its **honesty over completeness** contract. ADR-0012
added a Traefik front-end on that seam. Caddy is the third proxy an operator in
this fleet actually runs, and unlike Traefik (whose dynamic config is container
labels read via the compose reader), a **Caddyfile has its own grammar**. So the
Caddy front-end must carry a parser, not just a mapper.

Two Caddyfile-specific properties shape the work:

1. **`{` is overloaded.** It opens a block *and* begins a placeholder token
   (`{$DOMAIN}`, `{$DOMAIN:localhost}`, `{http.request.host}`). A naive brace
   scan reads a site address of `{$DOMAIN:localhost}` as "open an empty block".
2. **Directives are newline-terminated**, with an optional trailing `{ … }`
   block — unlike nginx's `;` terminator.

## Decision

We added `zion import caddy <Caddyfile>` as a third front-end that builds the
**same `ZionDoc`** and reuses ADR-0011's emitter, self-validation gate and
findings report unchanged (the `source` name was already threaded through
`emit::render`/`report_text` by ADR-0012). No shared-code change.

- **A tolerant Caddyfile reader** (`src/import/caddy.rs`), in the `nginx.rs`
  tradition: std-only, no directive whitelist (the mapper decides what Zion
  supports), line-preserving, `ParseError { line, msg }` on genuinely malformed
  input, and an anti-panic property test. The lexer disambiguates `{` at the
  point a token starts: a `{` immediately followed by a non-blank is a
  placeholder word read to its matching `}`; a `{` followed by whitespace /
  `}` / EOF is a block opener. Directive arguments are the tokens on the
  directive's own line; an immediately-following `{` opens its block. It parses
  the global-options block, snippet definitions `(name){…}` resolved by
  `import`, and site blocks.
- **`{$VAR}` / `{$VAR:default}` resolution** at import time from a `.env` next to
  the file plus `--var KEY=VALUE` (reused from the Traefik front-end); an
  unresolved required placeholder is a named `unsupported` finding, never an
  invented value.
- **TLS follows ADR-0012**: `tls <email>` / `tls internal` / `tls {…}` → a
  placeholder cert + a `partial` finding pointing at `[tls.acme]` / `zion init`;
  native ACME emission stays deferred. Explicit `tls <cert> <key>` files
  convert.

## Consequences

- **Positive**: the third fleet proxy becomes "one command + review" on the same
  trust contract. A pleasing result falls out of Zion's design: the Caddy
  `header` block **almost evaporates** — Zion already injects the same security
  headers, so `X-Content-Type-Options` / `X-Frame-Options` / `Referrer-Policy` /
  `Permissions-Policy` / `-Server` all land in `auto`, and `Content-Security-Policy`
  converts to `route.csp`. Zero new dependencies; the golden corpus
  `tests/fixtures/import/caddy/` is the executable spec.
- **Negative**: we own a ~400-line Caddyfile parser (bounded: the grammar is
  small). It reads a *declared subset* — the address-less single-site shorthand
  and mid-word `{$…}` placeholders are out of v0 and would be added when a real
  target needs them.
- **Neutral / risks**:
  - **Static serving is the product edge, stated loudly.** `root` / `file_server`
    (Zion serves nothing from disk), `handle_path` (no path rewriting) and
    `respond` (no static responses) are `unsupported`; a handler that only does
    these drops its route rather than emitting a wrong one.
  - **`{$}` resolution is mandatory**; a Caddyfile depending on runtime env the
    operator cannot supply at import time yields `unsupported` findings.
  - Third-party Caddy plugins (`waf`, `rule_file`, `cache`, …) are `unsupported`
    — Zion has no plugin surface to map them onto.

## Mapping contract (normative)

Statuses as in ADR-0011: **convert** / **partial** / **auto** / **unsupported**.

| Caddyfile | Status | Zion mapping / policy |
|---|---|---|
| site address `example.com` / `{$DOMAIN}` | convert | `hosts` (resolved from `.env` / `--var`) |
| site address `:80` / `:443` / `*` | convert | hostless route (Zion shared/default layer) |
| `handle [/matcher] { reverse_proxy up }` | convert | route (path from matcher) + upstream |
| bare `reverse_proxy [/matcher] up…` | convert | route + upstream (multiple targets → LB `urls`) |
| `/api/*` matcher | convert | `path = "/api/{*rest}"` |
| `/exact` matcher | convert | `path = "/exact"` |
| `@name` named matcher | unsupported | not converted (v0) |
| `reverse_proxy https://host` | convert | https upstream URL |
| `header X-Content-Type-Options` / `X-Frame-Options` / `Referrer-Policy` / `Permissions-Policy` | auto | Zion injects these built-in |
| `header -Server` | auto | Zion always strips `Server` |
| `header Strict-Transport-Security …` | partial | Zion sets HSTS built-in with a fixed `max-age` (63072000; not configurable) |
| `header Content-Security-Policy …` | convert | `route.csp` (site- or handler-scoped) |
| `header X-XSS-Protection …` | unsupported | not set (a no-op on modern browsers) |
| other `header …` | unsupported | no generic header-manipulation target |
| `tls <email>` / `tls internal` / `tls { … }` | partial | placeholder cert; add `[tls.acme]` / `zion init` |
| `tls <cert> <key>` | convert | `[tls]` `cert_path` / `key_path` |
| `protocols tls1.2 …` (in `tls`) | convert | `tls.min_version = "1.2"` |
| `import <snippet>` | convert | snippet inlined (same idea as nginx `include`) |
| `log { … }` | auto | structured JSON to stdout is built in |
| `auto_https` (global) | auto | driven by `[tls]`, not a global toggle |
| `email` (global) | — | captured to name the e-mail in the `tls` finding |
| `encode gzip zstd` | unsupported | Zion does not compress responses |
| `root` / `file_server` | unsupported | serves nothing from disk — the product edge |
| `handle_path /p/*` | unsupported | no path rewriting |
| `respond "…" <code>` | unsupported | no static-response directive |
| `redir …` | unsupported | HTTP→HTTPS is built in; no general redirect |
| `waf` / `rule_file` / `cache` / other plugins | unsupported | no Caddy-plugin surface to map |

**Report contract** (unchanged from ADR-0011/0012): one bucket per input;
stderr summary + `--report <file>`; `--strict` exits 2 on any partial/
unsupported; exit 0 converted, 1 fatal. `--var KEY=VALUE` supplies `{$VAR}`.

## Alternatives considered

- **A Caddyfile parser crate** — rejected against the ADR-0011 zero-dependency,
  MSRV-1.82 posture; the block-style grammar a ~400-line reader covers is small
  and stable, and the reader refuses rather than guessing.
- **Parse Caddy's JSON config instead of the Caddyfile** — rejected: operators
  write Caddyfiles; the JSON form is a compilation target they rarely hand-edit.
- **Map `caddy-waf`'s `waf` directive onto Zion's WAF** — rejected for v0: the
  rule semantics differ enough that an automatic mapping would be a guess.
  `unsupported` with a note is the honest call; a deliberate mapping can be an
  ADR of its own later.
- **Native `[tls.acme]` emission** — deferred, identical to ADR-0012's reasoning
  (it front-runs the cert-manager role case; a `partial` finding states the
  delta today).

## References

- ADR-0011 (`zion import` — nginx, honesty over completeness) and ADR-0012
  (Traefik front-end); the neutral `ZionDoc` seam and `emit::self_validate` gate
- `src/import/caddy.rs` — Caddyfile reader + mapper; `src/import/nginx.rs` — the
  tolerant-lexer pattern this follows
- `tests/fixtures/import/caddy/` — golden corpus (the executable spec)
- ADR-0007 (two-tier MSRV), ADR-0010 (host-based L7 routing)
