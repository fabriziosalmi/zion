# ADR-0014: native `[tls.acme]` emission in the importer

- **Status**: accepted
- **Date**: 2026-07-31
- **Deciders**: fabriziosalmi
- **Tags**: cli, migration, tls, acme, adoption

## Context

ADR-0012 (Traefik) and ADR-0013 (Caddy) each **deferred** native `[tls.acme]`
emission: a TLS route imported to a placeholder cert plus a `partial` finding,
and automatic HTTPS was left for the operator to add by hand. That was the right
call while the front-ends were being built, but with all three importer
front-ends landed (#320–#322) and the fleet swaps starting, the deferral is now
the thing standing between an imported config and a *real* swap — every live
HTTPS target (a Caddy auto-HTTPS site, a Traefik `certresolver` router) would
otherwise import to a cert that does not exist.

Feasibility is confirmed: Zion's `[tls.acme]` needs only `email` + `domains`
(the rest of `AcmeConfig` has defaults, and the block is `deny_unknown_fields`),
`validate_semantics`/`build_router_quiet` do not couple to it, and the
placeholder `cert_path`/`key_path` are exactly the bootstrap cert the ACME flow
expects so `:443` binds before the first issuance. An emitter test round-trips a
`[tls.acme]` document through `self_validate`.

## Decision

Resolve the deferral: the importer emits `[tls.acme]` when the source uses ACME
and a contact e-mail is known.

- **`ZionDoc` gains `acme: Option<AcmeOut { email, domains }>`**; `emit::render`
  writes a `[tls.acme]` block (with the bootstrap-cert comment) and only the two
  known fields. The bootstrap cert stays in `[tls]`.
- **E-mail source**, in precedence order: the source config's own ACME e-mail
  (Traefik `--certificatesresolvers.<r>.acme.email`, Caddy `tls <email>` or the
  global `email`), else the new **`--acme-email EMAIL`** CLI flag. An e-mail is
  never invented.
- **Domains** are the imported route hosts (Caddy restricts to non-localhost /
  non-IP hosts; a bare-port or localhost-only site gets no ACME).
- **Findings**: Traefik `certresolver` and Caddy ACME-managed `tls` move from
  `partial` to **`convert`** when an e-mail is available; with no e-mail they
  stay `partial` and name the fix (`--acme-email …`). Explicit Caddy
  `tls <cert> <key>` still converts to `[tls]` cert paths (no ACME).
- **The certificate-manager caveat is preserved, not auto-resolved**: when the
  origin is itself a cert manager, running ACME in parallel is wrong — but the
  importer cannot know that, so it faithfully translates the source's ACME
  intent and the finding notes the alternative (point `[tls]` at the existing
  cert). That stays a per-repo deployment decision.

## Consequences

- **Positive**: an HTTPS target now imports to a config that actually serves
  HTTPS. `zion import caddy Caddyfile --var DOMAIN=… --acme-email ops@…` yields a
  complete `zion.toml` with a real `[tls.acme]` — the missing half of a live
  swap. No new dependencies; only known `AcmeConfig` fields are emitted.
- **Negative**: one more doc-level aggregation in each front-end (union of route
  hosts → ACME domains) and a shared `AcmeOut` on the neutral seam.
- **Neutral / risks**: `[tls.acme]` is emitted only on explicit ACME intent
  (a source ACME directive) or an explicit `--acme-email` opt-in — never
  inferred from a public-looking hostname alone, so an import never silently
  turns on ACME the operator did not ask for.

## Alternatives considered

- **Keep deferring** — rejected: it is the blocker to real swaps now that the
  front-ends are done.
- **Invent / default an e-mail** — rejected: a wrong ACME account e-mail is worse
  than an honest `partial`. No e-mail → stay `partial`.
- **Emit `[tls.acme]` for every public-looking host** — rejected: importing a
  config should not silently enable ACME issuance; require an ACME signal or the
  `--acme-email` opt-in.

## References

- ADR-0012 / ADR-0013 (the deferral this resolves); ADR-0011 (the seam)
- `src/import/map.rs` (`AcmeOut`, `ZionDoc.acme`), `src/import/emit.rs`
  (`[tls.acme]` render + round-trip test), `src/import/traefik.rs` /
  `src/import/caddy.rs` (population + findings), `src/cli.rs` (`--acme-email`)
- `[tls.acme]` / `AcmeConfig` in `src/config.rs`, `src/acme.rs`
