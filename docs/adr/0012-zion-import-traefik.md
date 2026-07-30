# ADR-0012: `zion import traefik` — a second front-end on the neutral seam

- **Status**: accepted
- **Date**: 2026-07-30
- **Deciders**: fabriziosalmi
- **Tags**: cli, migration, traefik, docker-compose, adoption

## Context

ADR-0011 shipped `zion import nginx` as a four-stage pipeline whose last two
stages — a neutral `ZionDoc` (it describes Zion, not nginx) and a gated TOML
emitter — are already source-agnostic: `emit.rs` depends only on `ZionDoc`, and
`ZionDoc` knows nothing about nginx. ADR-0011 named a Caddyfile front-end as the
planned next step, but the reverse proxy an operator most commonly runs under
Docker is **Traefik**, configured through container *labels* (the Docker
provider) with static options as CLI flags on the Traefik service's `command`.
Extending the importer to Traefik pays twice: it makes those stacks mechanical,
and — Traefik being the most widespread Docker reverse proxy — it is itself the
outward-facing adoption feature.

Two properties of the Docker provider shape the design:

1. **The upstream host is the compose service name.** A router's backend is the
   container the `loadbalancer` labels sit on, so grepping labels out of a file
   is not enough — we must know which `services:` block each label belongs to.
   This is why a *reader* was needed, landed separately as the declared-subset
   compose reader (PR #320): it is deliberately not a YAML parser and refuses,
   with a line number, on anything outside the block-style subset compose files
   actually use.
2. **`zion.toml` does not expand `${VAR}`.** Real compose files write
   `` Host(`${DOMAIN:-localhost}`) `` and
   `--certificatesresolvers.le.acme.email=${ACME_EMAIL}`. An unresolved variable
   surviving to emission would fail `emit::self_validate` and surface as an
   "importer bug" — the worst possible message for the most mundane cause.

## Decision

We added `zion import traefik <compose>` as a second front-end that builds the
**same `ZionDoc`** and reuses the ADR-0011 emitter, self-validation gate and
findings report unchanged. The only shared-code change is that `emit::render`
now takes the source name so the generated header is honest about origin; the
nginx path — protected by its equivalence harness — is untouched.

- **Label mapper** (`src/import/traefik.rs`): reads exactly the router / service
  label families and static flags observed across real fleet stacks (table
  below) and, per ADR-0011's **honesty over completeness**, drops a route with a
  loud `unsupported` finding on any matcher it does not understand rather than
  guessing.
- **Variable resolution is a precondition, not a convenience.** Variables are
  resolved at import time from a `.env` next to the compose file (compose
  convention) plus repeatable `--var KEY=VALUE` overrides that win over `.env`.
  `${VAR}`, `${VAR:-default}` and `${VAR:?msg}` are honored; an unresolved
  required variable becomes a named `unsupported` finding with its line — never
  an invented value, never a crash.
- **The finding written first.** `--providers.docker=true` maps to `auto`, but
  it is the single biggest semantic delta and leads the report: Zion has no
  service discovery, so **routes are frozen at import time** — a container added
  to the stack later is not exposed until the import is re-run.
- **TLS is scoped honestly for v0.** `ZionDoc`/`emit` are *not* extended with a
  `[tls.acme]` block here. `tls=true` and `tls.certresolver=…` both produce an
  HTTPS route with a placeholder cert (the nginx path's convention) plus a
  `partial` finding that names the next step — provide `[tls]` cert/key or
  `[tls.acme]`, or run `zion init`, and if the origin is itself a certificate
  manager, point `[tls]` at its cert rather than issuing in parallel. Native
  ACME emission is deferred deliberately (see Alternatives).

## Consequences

- **Positive**: the most common Docker reverse-proxy shape becomes "one command
  + review", on the same trust contract as nginx. Zero new dependencies (the
  reader and mapper are std-only, MSRV-1.82 core; no cargo-vet/deny churn). The
  golden corpus `tests/fixtures/import/traefik/` (anonymized fleet shapes + a
  no-upstream pathological case) is the executable spec and regression net,
  exercised end-to-end through `convert` → `self_validate`.
- **Negative**: a second mapping surface to keep in step with Traefik idioms and
  Zion's schema. The compose reader is a declared *subset* of YAML, by design: a
  compose file using anchors, merge keys or multi-document streams is refused
  with a line number, not parsed.
- **Neutral / risks**:
  - **Frozen routes are the headline delta**, stated as the lead finding, not a
    footnote. Operators who rely on Traefik auto-discovering new containers must
    know the imported config is a point-in-time snapshot.
  - **`${}` resolution is mandatory**; a stack that depends on runtime env the
    operator cannot supply at import time will emit `unsupported` findings rather
    than a wrong config.
  - **Placeholder TLS for v0**: an HTTPS route binds `:443` but serves a
    placeholder cert until the operator supplies one or adds `[tls.acme]`. The
    `partial` finding is the safety valve.

## Mapping contract (normative)

Statuses as in ADR-0011: **convert** / **partial** / **auto** / **unsupported**.
The compose service carrying the labels is the upstream host.

| Traefik (label or `command` flag) | Status | Zion mapping / policy |
|---|---|---|
| `traefik.enable=true` | — | gate: a service without it is not routed (matches `exposedbydefault=false`) |
| `` routers.<r>.rule=Host(`a`) `` | convert | `hosts += ["a"]` |
| `` … \|\| Host(`b`) `` | convert | `hosts += ["b"]` |
| `` … && PathPrefix(`/api`) `` | convert | `path = "/api/{*rest}"` |
| `` PathPrefix(`/api`) `` alone | convert | route with no `hosts` (Zion shared/default layer) |
| `` Path(`/x`) `` | convert | `path = "/x"` (exact) |
| `Host` argument with `${VAR}` | convert\* | resolved from `.env` + `--var`; \*unresolved → `unsupported` (named, line), route dropped |
| regex / `Query()` / `Header()` / `HostRegexp()` matchers | unsupported | route dropped with a finding — never mistranslated |
| `services.<s>.loadbalancer.server.port=8000` | convert | `[upstream.<svc>] url = "http://<svc>:8000"` |
| router with no resolvable port | unsupported | no upstream can be built; route dropped |
| `routers.<r>.entrypoints=web` / `websecure` | auto | Zion serves both listeners; entrypoint is informational |
| `routers.<r>.tls=true` | partial | HTTPS route + placeholder cert; supply `[tls]` cert/key or `[tls.acme]` |
| `routers.<r>.tls.certresolver=le` (+ `acme.email`) | partial | placeholder cert; ACME e-mail echoed in the finding; add `[tls.acme]`, or point `[tls]` at an existing cert manager's cert |
| router on `/.well-known/acme-challenge` | auto | Zion answers HTTP-01 in memory before routing; router dropped |
| `--providers.docker=true` | auto | **the lead finding** — no service discovery; routes frozen at import; re-run to expose a new service |
| `--providers.docker.exposedbydefault=false` | auto | only `enable=true` services are imported |
| `--entrypoints.web.address=:80` / `.websecure.address=:443` | convert | `server.listen_http` / `listen_https` |
| `--entrypoints.web.http.redirections.*` | auto | HTTP→HTTPS redirect is built in (collapsed to one finding) |
| `--api.insecure=true` / `--api.dashboard=true` | unsupported | Zion has no admin dashboard |
| `--certificatesresolvers.<r>.acme.email=` | — | captured to name the e-mail in the certresolver `partial` finding |
| `--log.*` | auto | structured JSON logging to stdout is built in |
| middleware `ratelimit` | partial | only the global `[server].rate_limit_rps` exists |
| middleware `stripprefix` / path rewriting | unsupported | no path rewriting (ADR-0011 product edge) |
| `traefik.tcp.*` / `traefik.udp.*` | unsupported | Zion is an L7 proxy |

**Report contract** (unchanged from ADR-0011): every input lands in exactly one
bucket; stderr gets the summary, `--report <file>` the full log; `--strict`
exits 2 on any partial/unsupported. Exit codes: 0 converted, 1 fatal (nothing
emitted), 2 strict findings. New flag: repeatable `--var KEY=VALUE`.

## Alternatives considered

- **Extend `ZionDoc`/`emit` with a native `[tls.acme]` block now** — would make
  `certresolver` a clean `convert`. Deferred: it front-runs an undecided
  deployment question (when the origin is itself a certificate manager, Zion
  should *consume* its cert, not issue ACME in parallel), and the low-risk
  target shapes need no ACME emission. Kept out of the critical path; a
  `partial` finding states the delta today, and the follow-up is an
  `emit`-level addition that does not touch this front-end.
- **A real YAML parser (`serde_yaml` / `yaml-rust`)** — rejected: a new
  dependency against the ADR-0011 zero-dep, MSRV-1.82 posture, for a file whose
  block-style subset a ~30-key reader covers. `yaml-rust` is also on the
  supply-chain ignore list already. The declared-subset reader refuses rather
  than guessing.
- **Parse Traefik's dynamic-config files (`*.yml`/`*.toml`) instead of labels**
  — rejected: the fleet runs the *Docker provider*, where routing lives in
  container labels and the backend identity *is* the compose service. A
  file-provider parser would miss the actual input.
- **Honor `--providers.docker` as live discovery** — rejected: Zion is a
  static-config proxy with hot-reload, not a service-discovery agent. This gap
  is not hidden; it is the lead finding.
- **Caddyfile front-end first** (ADR-0011's stated next step) — reordered:
  Traefik has the larger Docker installed base among the real targets. Caddy
  remains the planned third front-end on the same `ZionDoc` seam.

## References

- ADR-0011 (`zion import` — nginx, honesty over completeness); the neutral
  `ZionDoc` seam and `emit::self_validate` gate this ADR reuses
- PR #320 — the declared-subset Docker Compose reader (`src/import/compose.rs`)
- `src/import/traefik.rs` — label + static-flag mapper and `${}` resolution;
  `src/import/emit.rs` — `render(doc, source)`
- `tests/fixtures/import/traefik/` — golden corpus (the executable spec)
- ADR-0007 (two-tier MSRV), ADR-0010 (host-based L7 routing)
- Traefik Docker-provider label reference; `[tls.acme]` / `AcmeConfig` in
  `src/config.rs`, `src/acme.rs`
