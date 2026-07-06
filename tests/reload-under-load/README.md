# Reload-under-load harness

On a fleet you reload `zion.toml` often — a new route, a changed upstream, a
tweaked rate limit. The swap must be **invisible to live traffic**: not one
in-flight request may be dropped, reset, or mis-routed while the config
changes underneath it. Zion swaps config with an atomic `ArcSwap` store
precisely so this holds; this harness proves it under real load.

## What it does

`run.sh` starts a real Zion (+ the bench backend), then:

1. fires **sustained concurrent traffic** — N workers hammering a WAF-gated
   route for a fixed duration,
2. triggers **many real config swaps** *while the traffic is flowing* via
   `POST /admin/reload` (the same `reload_now` atomic swap the file watcher
   uses — every call stores a freshly-built snapshot, so each is a genuine
   swap, and it skips the file watcher's 2 s debounce so the test is
   deterministic),
3. asserts:
   - **zero failed requests** across the whole run (no transport error, no
     non-2xx, no timeout), and
   - the config **generation actually advanced during the load** — i.e. the
     swaps really happened concurrently with traffic, not before or after it.

A single dropped connection during any swap makes the run fail.

## Run it

Requirements: `curl`, `openssl`, `bash`, and a release build of Zion + the
bench backend (the harness builds them if absent). No Docker.

```console
$ ./tests/reload-under-load/run.sh
  ...
  requests: 5334 ok, 0 failed
  config swaps during load: 20 (generation 0 → 20); admin reloads acked: 20/20
  PASS — 5334 requests, 0 dropped across 20 live config swaps.
```

Tunable via env: `DURATION` (seconds, default 15), `WORKERS` (default 24),
`RELOADS` (default 30). Prebuilt binaries: `ZION_BIN`, `BACKEND_BIN`.

CI (`.github/workflows/reload-under-load.yml`) runs it on every change to the
reload/dispatch/config path, so a regression that makes a swap drop
connections is caught before merge.
