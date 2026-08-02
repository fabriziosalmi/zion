# ADR-0022: Precompressed static sidecars (`.br` / `.gz` via Accept-Encoding)

- **Status**: accepted
- **Date**: 2026-08-02
- **Deciders**: fabriziosalmi
- **Tags**: static, compression, http, rfc-9110

## Context

The last of the ADR-0015 static follow-ups (after conditional GET / range /
streaming — ADR-0019/0020/0021). A build pipeline typically emits `app.js`
alongside `app.js.br` and `app.js.gz`; nginx (`gzip_static`) and Caddy
(`precompressed`) serve the precompressed sibling when the client accepts it,
saving bandwidth without compressing on the fly. Zion's `mode = "static"` served
only the identity file. This closes the parity gap.

## Decision

### Opt-in per route (`precompressed = true`), not always-on

A new `precompressed` route flag (default `false`) gates the behavior. Rationale:
zero cost — and zero extra `stat`s — when off; and it avoids a nasty surprise
where a stale `app.js.gz` left in a docroot from an old build would suddenly be
served. This matches the opt-in semantics operators already expect from
`gzip_static` / `precompressed`, and Zion's own opt-in idiom (mode=static, cors,
auth are all opt-in).

### Serve the sidecar's bytes with the *original's* Content-Type

When a sidecar is chosen, the response carries the sidecar file's **bytes** and
its own validators (a `.br` variant is a distinct representation, so its weak
ETag naturally differs — correct per RFC 9110 §8.8.1), but the **`Content-Type`
of the original file** (`app.js.br` is `text/javascript`, not
`application/octet-stream`) plus `Content-Encoding: br|gzip`. Zion **never
compresses** — sidecars only — keeping the hot path allocation-free and pulling
in no compression dependency.

### Brotli preferred; minimal Accept-Encoding parsing

Codings are tried in preference order **br → gzip** (Brotli's better ratio), and
the first that the client accepts *and* has a sidecar for wins. `Accept-Encoding`
parsing is deliberately small: a coding is acceptable if it (or `*`) appears with
a non-zero q-value — enough for asset negotiation, not a full q-ranking.

### `Vary: Accept-Encoding` on every response from the route

Every response a precompressed route emits — the encoded variant **and** the
identity fallback — carries `Vary: Accept-Encoding`, so a shared cache keys on it
and never hands a `br` body to a client that didn't ask for one. This is the
correctness lynchpin of content negotiation.

### The sidecar goes through the same path-safety guard

`<file>.br` / `<file>.gz` is resolved with the identical `canonicalize` +
under-root check as the primary file (`resolve_sidecar`), so a sidecar that is a
symlink out of the tree is refused and the request falls back to identity — the
file server's one security property (never read outside `serve_dir`) holds for
sidecars too. Conditional GET and range apply to whatever representation was
selected, unchanged.

## Consequences

- **Positive**: bandwidth parity with nginx/Caddy for precompressed assets; no
  compression on the hot path, no new dependency; opt-in keeps every existing
  static route byte-for-byte unchanged (no `Vary`, no extra `stat`).
- **Neutral / risks**: an operator must generate the sidecars (Zion won't); a
  missing `.br` with a present `.gz` falls through correctly, but a *stale*
  sidecar (out of sync with the source) would be served as-is — the opt-in flag
  and the build pipeline's discipline are the mitigation. `*` in `Accept-Encoding`
  is treated as accepting Brotli, which is spec-correct but means a `*`-only
  client gets `br`.

## Alternatives considered

- **Always-on (no flag)** — rejected: 1–2 extra `stat`s and a `Vary` header on
  every static response, plus the stale-sidecar surprise, for a feature most
  routes don't use.
- **On-the-fly gzip/br compression** — rejected (for now): a compression
  dependency and CPU on the hot path, when the asset pipeline already produces
  better-compressed sidecars offline. Precompressed sidecars are the 90% case.
- **Full RFC 9110 q-value ranking** — deferred: real `Accept-Encoding` headers
  from browsers are simple (`gzip, deflate, br`); token+q=0 handling covers them
  without a parser worth maintaining.

## References

- ADR-0015 (`mode = "static"`), ADR-0019/0020/0021 (the sibling runtime
  follow-ups this completes)
- RFC 9110 §8.4 (Content-Encoding), §12.5.3 (Accept-Encoding), §8.8.1 (validators
  per representation), §12.5.5 (Vary)
- `src/static_files.rs` (`serve_resolved`, `resolve_sidecar`, `accepts`,
  `apply_negotiation_headers`), `src/config.rs` (`precompressed` route flag)
- A future importer hook could map nginx `gzip_static on` / Caddy `precompressed`
  → `precompressed = true` (on-demand, per the backlog).
