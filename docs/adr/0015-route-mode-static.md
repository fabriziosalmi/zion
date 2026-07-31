# ADR-0015: `mode = "static"` — opt-in disk file serving

- **Status**: accepted
- **Date**: 2026-07-31
- **Deciders**: fabriziosalmi
- **Tags**: routing, static, security, adoption

## Context

ADR-0011/0012/0013 each stated "Zion serves nothing from disk" as the **product
edge**, mapping nginx `root`/`try_files` and Caddy `root`/`file_server` to
`unsupported`. That kept Zion a pure L7 proxy. But a large share of the fleet's
stacks serve static assets *alongside* a proxy (a built SPA + an API backend),
and the migration thesis is "one binary in place of the stack, not one more
container". Swapping those stacks without regressing to an extra static-file
container requires Zion to serve those files itself. With the importer front-ends
and ACME emission landed, this is the next unblock.

## Decision

Relax the edge with an **opt-in** route mode; the default posture is unchanged (a
route is a proxy unless it says otherwise).

- **`RouteMode::Static`** + `RouteConfig.serve_dir` (the directory) and
  `spa_fallback` (serve `index.html` for an unmatched path — single-page apps).
  A static route has **no upstream**; validation requires `serve_dir` instead and
  skips the upstream-reference check. The serve dir is *not* canonicalized at
  load, so an imported config still validates offline; existence is a per-request
  check.
- **Serving** (`src/static_files.rs`): GET/HEAD only; a directory maps to its
  `index.html`; MIME by a small closed extension table (no `mime_guess`
  dependency); 404 on a miss (or the SPA `index.html` when `spa_fallback`).

### Security model (the load-bearing part)

The only property that matters is that a request can never read a file outside
`serve_dir`. Defense in depth, all covered by adversarial tests:

1. **Per-segment percent-decode**, refusing a decoded `/`, `\`, NUL byte or
   invalid UTF-8 — so `%2f`, `%00` and encoded traversal cannot smuggle path
   structure past the checks.
2. **Refuse `..` and dotfile segments outright** — `..` is never normalized, and
   any segment starting with `.` (`.env`, `.git`, `.ssh`) is refused.
3. **`canonicalize` + containment** — the resolved path and the root are both
   canonicalized and the resolved path must stay under the root. This is what
   defeats a symlink inside the tree that points out of it (proven by a
   `symlink_escaping_the_root_is_refused` integration test).

No directory listing, no dotfiles, no methods beyond GET/HEAD. `sanitize` is pure
and exhaustively unit-tested; the filesystem path is integration-tested against a
real temp tree.

## Consequences

- **Positive**: the Tier B static-and-proxy stacks become swappable with a single
  Zion binary. The default stays a proxy; static serving is opt-in per route.
- **Negative**: a file server is new attack surface. It is mitigated by the
  layered path defense, the GET/HEAD gate, the no-listing / no-dotfile policy, and
  the closed MIME table — but it is surface that did not exist before, hence this
  ADR and the adversarial test suite.
- **Neutral / risks**: v1 reads each file fully into memory (fine for typical
  static assets). Streaming, HTTP range requests and conditional GET (ETag /
  If-Modified-Since) are deferred follow-ups. The importer still maps
  `root`/`file_server`/`try_files` to `unsupported`; mapping them to `mode=static`
  `convert` is a follow-up PR (this ADR unblocks it).

## Relationship to the "no disk serving" edge

This is a **follow-up** that relaxes the edge ADR-0011/0012/0013 stated — not a
supersession. Those ADRs stay `accepted`; their "honesty over completeness"
contract is untouched, and the importer's product-edge findings simply gain a
faithful target to convert to.

## Alternatives considered

- **Keep the edge** — rejected: it blocks the Tier B swaps, which are the point.
- **A sidecar static-file container** — rejected: it defeats "one binary, not one
  more container".
- **A static-file crate (`tower-http` `ServeDir`, …)** — rejected: new
  dependencies against the zero-dep posture, and we want to *own* the
  security-critical path-resolution rather than delegate it.

## References

- ADR-0011 / 0012 / 0013 (the "no disk serving" edge this relaxes)
- `src/static_files.rs` (sanitize + serve + adversarial tests),
  `src/config.rs` (`RouteMode::Static`, `serve_dir`, validation),
  `src/dispatch.rs` (the `Static` arm)
