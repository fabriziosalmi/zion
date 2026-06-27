# CLI reference

Zion is a single binary. Run with no arguments it is the gateway **daemon**;
a handful of subcommands cover bootstrapping a config, a live dashboard, and
diagnostics.

```console
$ zion                          # run the gateway daemon (default)
$ zion auto --upstream :3000    # one-shot dev mode — TLS in front of a backend, no files
$ zion init                     # scaffold a zion.toml (interactive or flags)
$ zion suggest                  # synthesize a validated zion.toml from a detected backend
$ zion top                      # live TUI dashboard
$ zion doctor                   # environment diagnostics
$ zion bootstrap                # dump detected platform as JSON (CI / automation)
$ zion --version | --help
```

## The daemon (default)

With no subcommand Zion loads its config and serves. The config path comes from
`ZION_CONFIG` (default `zion.toml`):

```console
$ ZION_CONFIG=/etc/zion/zion.toml zion
```

The config file (and the cert files it references) are **hot-reloaded** — see
[Hot-reload](/deploy/hot-reload).

## `zion auto` — zero-config dev mode

Put TLS + HTTP/2 in front of a local backend with no config files at all — a
self-signed cert is generated in memory. Ideal for local development.

```console
$ zion auto --upstream :3000          # 127.0.0.1:3000 behind https://localhost:8443
```

| Flag | Default | Meaning |
|---|---|---|
| `-u, --upstream HOST:PORT` | — | backend to proxy (`:3000` → `127.0.0.1:3000`) |
| `--http-port <N>` | 8080 | HTTP listen port |
| `--https-port <N>` | 8443 | HTTPS listen port |
| `--hostname <H>` | localhost | SAN for the self-signed cert |

## `zion init` — scaffold a config

Generate a `zion.toml` interactively (prompts) or non-interactively from flags.

| Flag | Default | Meaning |
|---|---|---|
| `-o, --output <PATH>` | `zion.toml` | output path |
| `-f, --force` | — | overwrite an existing config |
| `-y, --non-interactive` | — | skip prompts; use defaults + flags |
| `--hostname <H>` | — | hostname Zion will serve |
| `--upstream NAME=HOST:PORT` | — | declare an upstream (repeatable) |
| `--http-port <N>` / `--https-port <N>` | 80 / 443 | listener ports |
| `--no-tls` | — | skip self-signed cert generation |
| `--no-waf` | — | skip WAF on `/api/*` routes |

## `zion suggest` — synthesize from a detected backend

`suggest` goes from "I have a backend running" to a **validated** `zion.toml`
with near-zero hand-editing — deterministic, no ML. It detects an upstream (an
explicit `--upstream`, else a bounded scan of common localhost dev ports),
synthesizes a TLS + WAF-protected `/api` route plus a catch-all, and
**self-validates the result against the config schema before emitting it** — it
never prints a config the daemon would reject. The only thing left for you is to
set real `[tls]` cert paths.

| Flag | Meaning |
|---|---|
| `--upstream <host:port>` | upstream hint (`:3000`, `3000`, `127.0.0.1:3000`, `api.internal:8080`); a bare port binds `127.0.0.1` |
| `--domain <name>` | domain for the synthesized cert paths (default `localhost`) |
| `--write <path>` | write to a file instead of stdout |

```console
$ zion suggest --upstream :3000 --domain app.example.com --write zion.toml
  wrote a validated config to zion.toml
  next: set real [tls] cert paths (or `zion init`), then ZION_CONFIG=zion.toml zion

# or detect automatically and pipe:
$ zion suggest > zion.toml
  detected a listening backend at 127.0.0.1:3000
```

If no backend is found and no `--upstream` is given, `suggest` exits non-zero with
a hint rather than emitting a guess.

## `zion top` — live dashboard

A terminal dashboard that polls a running Zion's snapshot endpoint.

| Flag | Default | Meaning |
|---|---|---|
| `-u, --url <URL>` | `http://127.0.0.1:80/_zion/snapshot.json` | snapshot endpoint |
| `-i, --interval <MS>` | 500 | poll interval (100–10000) |

## `zion doctor` — diagnostics

Validates the deployment without serving: parses + validates the config, probes
upstream reachability, and warns on weak posture (rate-limiting off, WAF
coverage gaps). See [Observability](/deploy/observability).

## `zion bootstrap` — platform JSON

Prints the detected platform (cores, CPU features, tier, kernel capabilities) as
JSON — for CI gating and automation.

## Environment variables

| Variable | Meaning |
|---|---|
| `ZION_CONFIG` | config path for the daemon (default `zion.toml`) |
| `ZION_BOOT_PLAIN=1` | disable ANSI colors in boot output |
| `NO_COLOR=1` | honored — same as `ZION_BOOT_PLAIN` |
