# Architecture Decision Records

Short, dated, in-repo records of the load-bearing engineering choices
that shape Zion. Each ADR is a one-page capture of the *why* behind
something a future maintainer would otherwise have to reverse-engineer
from `git log`.

Format: [MADR](https://adr.github.io/madr/) (Markdown ADRs), variant
defined in [0000-template.md](0000-template.md).

## Index

| #     | Title                                                              | Status   |
|-------|--------------------------------------------------------------------|----------|
| 0001  | [ArcSwap for config + TLS hot-reload](0001-arcswap-config-hot-reload.md) | accepted |
| 0002  | [Aho-Corasick over regex for the WAF scanner](0002-aho-corasick-over-regex.md) | accepted |
| 0003  | [Two-level cache with per-snapshot generation counter](0003-two-level-cache-with-generation.md) | accepted |
| 0004  | [HMAC-SHA256-chained audit log](0004-hmac-chained-audit-log.md)    | accepted |
| 0005  | [Distroless image, SLSA L3 provenance, cosign keyless signatures](0005-distroless-with-cosign-slsa.md) | accepted |
| 0006  | [`tracing` always-on, OTLP gated by `--features otel`](0006-tracing-with-optional-otlp.md) | accepted |
| 0007  | [Two-tier MSRV — 1.82 core, 1.88 with optional features](0007-bicapa-msrv.md) | accepted |
| 0008  | [Embed AIMP as the mesh control-plane bus](0008-mesh-aimp-integration.md) | accepted |
| 0010  | [Host-based L7 routing (virtual hosting)](0010-host-based-l7-routing.md) | accepted |
| 0011  | [`zion import` — nginx config migration, honesty over completeness](0011-zion-import-nginx.md) | accepted |
| 0012  | [`zion import traefik` — a second front-end on the neutral seam](0012-zion-import-traefik.md) | accepted |
| 0013  | [`zion import caddy` — third front-end, own Caddyfile parser](0013-zion-import-caddy.md) | accepted |
| 0014  | [Native `[tls.acme]` emission in the importer](0014-importer-tls-acme-emission.md) | accepted |
| 0015  | [`mode = "static"` — opt-in disk file serving](0015-route-mode-static.md) | accepted |
| 0016  | [nginx `root`/`try_files`/`index` → `mode = "static"`](0016-importer-nginx-static-mapping.md) | accepted |
| 0017  | [Audit-log rotation with per-segment chain re-anchoring](0017-audit-log-rotation.md) | accepted |
| 0018  | [Cache origin-side revalidation (RFC 9111 §4.3)](0018-cache-origin-revalidation.md) | accepted |
| 0019  | [Static file conditional GET (ETag / Last-Modified → 304)](0019-static-conditional-get.md) | accepted |
| 0020  | [Static file range requests (206 Partial Content)](0020-static-range-requests.md) | accepted |

## When to write a new ADR

- A choice between two or more reasonable approaches with non-trivial
  trade-offs (performance, security, ergonomics).
- A change to an external contract (HTTP, file, registry, log format).
- A choice that locks us into a vendor / crate / protocol we'd find
  costly to replace later.

When in doubt, write one. The cost of a stale ADR is "delete it";
the cost of a missing ADR is a multi-week archaeology trip.

## When not to write an ADR

- Pure refactors with no observable contract change.
- Bug fixes.
- Anything captured well by the commit message / PR description.

## Lifecycle

ADRs are immutable once accepted. To revisit, write a new ADR that
**supersedes** the old one and update the old one's status:

```markdown
- **Status**: superseded by ADR-NNNN
```

Never edit the body of an accepted ADR — write a follow-up.
