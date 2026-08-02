# Equivalence harness — `zion import <nginx|caddy|traefik>`

The migration pitch for [`zion import`](../../docs/adr/0011-zion-import-nginx.md)
is only as good as its proof. This harness produces that proof with **real
instances, no mocks**: it converts an incumbent proxy config, then shows that
real Zion serving the converted config routes requests the same way the real
proxy serving the original does — and that the handful of intentional
differences are exactly the ones the import report already flagged.

The **source is auto-detected** from the scenario directory:

| file present | source | how the original runs |
|---|---|---|
| `nginx.conf` | nginx | real `nginx:alpine`, echo backends on `zeq-net` |
| `Caddyfile` | caddy | real `caddy:alpine`, echo backends on `zeq-net` |
| `docker-compose.yml` | traefik | real traefik via `docker compose up` (the compose file provides its own label-routed backends; needs `docker compose`) |

Shipped scenarios: `multi-vhost` (nginx), `caddy-basic` (caddy), `traefik-compose`
(traefik). Each column of the corpus is verified — Zion's live against the
imported config, the incumbent's against the original.

## What it does

For a scenario, `run.sh`:

1. starts the **real original proxy** on the scenario's config,
2. runs **`zion import <src>`** on that *same* config and prints the findings,
3. starts **real Zion** on the converted `zion.toml`,
4. replays every `(Host, path)` request in the corpus against **both**,
5. diffs the backend that answered — request by request.

Each backend is a tiny server that returns its own name, so "which backend
answered" *is* the routing decision. The exit code is the verdict: `0` only
when every request either matched identically or diverged **exactly** as the
import report declared.

## Documented divergences are first-class

Zion is not a byte-for-byte nginx clone, and the ADR-0011 honesty contract
says so out loud. The corpus therefore includes rows where nginx and Zion are
*expected* to differ — for example nginx's default-server returning 404 for an
unmatched path where Zion's shared layer forwards it. Those rows are asserted,
labelled "documented divergence", and cross-checked against the import
report's partial findings. The harness passes because the differences are the
declared ones, not because there are none.

## Run it

Requirements: `docker`, `curl`, `openssl`, `bash`. No Rust toolchain needed —
Zion runs from its published container image.

```console
$ ./tests/equivalence/run.sh                 # default scenario: multi-vhost
$ ./tests/equivalence/run.sh multi-vhost     # explicit
```

Environment:

| Variable | Meaning |
|---|---|
| `ZION_IMAGE` | Zion image to test (default: the pinned release) |
| `ZION_BIN` | path to a locally built **linux** `zion` binary; mounts it into `ZION_RUNTIME_IMAGE` instead of pulling `ZION_IMAGE` — this is how CI tests the working tree |
| `ZION_RUNTIME_IMAGE` | runtime base for `ZION_BIN` (default `ubuntu:24.04`) |
| `KEEP=1` | leave the containers running for debugging |

CI (`.github/workflows/equivalence.yml`) runs the harness in `ZION_BIN` mode
against a binary built from the branch, so a regression in the mapper is
caught before merge.

> **arm64 note:** the default `ZION_IMAGE` (the published multi-arch image)
> currently ships an x86-64 binary in *both* the amd64 and arm64 manifests, so
> on an arm64 host the image mode fails to exec. Until that release-pipeline
> defect is fixed, run the harness on arm64 with `ZION_BIN` (a locally built
> binary), which is also the CI path.

## Add a scenario

Create `scenarios/<name>/`:

- `nginx.conf` — a realistic config; backends are referenced as
  `http://zeq-be-<id>:5678` (the harness spins up one echo backend per `<id>`
  it finds).
- `requests.txt` — rows of `HOST PATH EXPECT_NGINX EXPECT_ZION`. Use the
  backend id for a proxied hit, or an HTTP status (`404`) for a miss. When the
  two expectations differ, the row is a documented divergence and should
  correspond to a partial finding in the import report.
