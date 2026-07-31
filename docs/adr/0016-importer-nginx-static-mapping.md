# ADR-0016: nginx `root`/`try_files`/`index`/`alias` → `mode = "static"`

- **Status**: accepted
- **Date**: 2026-07-31
- **Deciders**: fabriziosalmi
- **Tags**: import, static, nginx, adoption

## Context

ADR-0015 gave Zion an opt-in disk file server (`mode = "static"`), and the caddy
front-end already maps `root` + `file_server` to it (#325). The nginx front-end
(ADR-0011) still routed `root`/`try_files`/`index` to `unsupported` — the last
place the "no disk serving" product edge survived in the importer.

The dominant Tier B stack is the **nginx single-page app**: a build directory
served with `try_files $uri $uri/ /index.html` under an inherited `root`, next to
a proxied `/api`. Without this mapping such a stack imports to a config that
serves nothing, and the "one binary in place of the stack" thesis breaks. This
ADR completes the importer's static mapping so those stacks convert in one pass.

## Decision

A `location` with **no `proxy_pass`** but an explicit static signal
(`try_files` / `root` / `alias` / `index` / `autoindex`) becomes a
`mode = "static"` route. A proxy-less location with none of those (only
`expires`/`access_log`) stays skipped — a catch-all static route already serves
it at runtime.

### serve_dir semantics — the load-bearing decision

nginx `root R` and Zion `mode = "static"` treat the request path *differently*,
and the difference cancels exactly:

- nginx `root R` **appends the whole request URI** to `R`
  (`/assets/app.js` → `R/assets/app.js`).
- Zion `mode = "static"` **strips the route's static prefix**, then appends the
  remainder to `serve_dir`.

So `serve_dir = R joined with the location prefix` reproduces the identical
on-disk path: `location /assets/ { root /srv; }` → `serve_dir = "/srv/assets"`,
and `/assets/app.js` lands on `/srv/assets/app.js` under both. For the catch-all
`location /` the prefix is empty and `serve_dir = R`.

`alias A` is the other case: nginx `alias` **replaces** the location prefix (it
already strips it, exactly like Zion), so it maps to `serve_dir = A` directly, no
join. This is an exact translation, not an approximation — the ADR-0011 honesty
contract holds.

### spa_fallback and honest findings

- `try_files` fallback (its last argument): `/index.html` → `spa_fallback = true`
  (`convert`); `=404`/`=CODE` → no SPA (`convert`); a *different* file → SPA on,
  plus a `partial` (Zion's fallback always serves the docroot `index.html`); a
  named location `@name` → `partial`, no SPA (not modeled).
- No `try_files` (just `root`/`index`) → directory serving; Zion serves
  `index.html` for a directory, so `index index.html` is the default (`convert`)
  and any other `index` is a `partial`.
- `root` with an unresolved variable (`$host`) or empty → `unsupported`.
- `autoindex on` → `partial` (no directory listing).
- **Exact-match** static (`location = /x`) → `unsupported` (write it by hand);
  regex locations are already excluded upstream.
- A **server-level `root` that no static location consumed** → `unsupported`
  ("set but no static location uses it — ignored"), so a defensive docroot on a
  proxy-only server is not silently dropped.

## Why the equivalence harness is not extended

`tests/equivalence/` is a **routing-decision** differ: it replays a corpus and
diffs *which backend answered*, request by request. Static serving is file I/O,
not a routing decision — there is no backend to name. It is covered instead by
`src/static_files.rs` (adversarial path-safety unit tests), the `t31` integration
test (a static route serves a file, not a 503), and the deterministic import
matrix in `src/import/mod.rs`. The `multi-vhost` corpus is pure proxy and is
provably unaffected by this change (it contains no `root`/`try_files`/`index`). A
byte-for-byte static **parity** leg (a shared docroot mounted into both nginx and
Zion) belongs to the swap gates run on the host, and is deferred to that work
rather than bolted onto the routing differ.

## Consequences

- **Positive**: the Tier B nginx SPA-plus-proxy stacks convert in a single pass;
  the importer's product-edge findings for nginx now have a faithful target.
- **Negative**: none new — this is a mapping onto the ADR-0015 file server, whose
  attack surface and defenses are unchanged.
- **Neutral / risks**: sub-path `root` joining is covered by tests, but v1 does
  not convert exact-match static locations or rewrite paths (`strip_prefix` stays
  out of scope per ADR-0011 until a real target needs it).

## Relationship to earlier ADRs

A **follow-up**, not a supersession. ADR-0011 (nginx import) stays `accepted`;
this adds the static bucket to its mapping. ADR-0015 (`mode = "static"`) stays
`accepted`; this is the nginx sibling of the caddy mapping (#325) that targets it.

## References

- ADR-0011 (nginx import contract), ADR-0015 (`mode = "static"`)
- `src/import/map.rs` (`map_location` static branch, `classify_try_files`)
- `src/import/mod.rs` (the `static_*` deterministic matrix)
- `tests/fixtures/import/nginx/04-static-plus-proxy.conf` (the SPA-plus-proxy corpus)
