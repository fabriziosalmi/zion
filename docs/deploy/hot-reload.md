# Hot-reload

Zion watches its config file (the path in `ZION_CONFIG`, default `zion.toml`) and the certificate files referenced by `[tls]`. When either changes, the running process applies the change without a restart and without dropping in-flight connections. There is no admin endpoint, no SIGHUP, no orchestrator dance — edit the file, save, the change is live.

This page is the contract: what reloads, what doesn't, what survives, and how to verify it landed.

## Trigger

| Source | What it triggers |
|---|---|
| Edit + save `zion.toml` | Re-parse → re-validate → atomic-swap of every config-derived state (routes, upstreams, WAF profiles, CORS, rate-limit, XFF policy, trusted proxies). 2-second debounce collapses editor write/rename/modify bursts into a single reload. |
| Edit + save a cert/key file referenced by `[tls]` | Rebuild of the TLS `ServerConfig` and atomic swap of the acceptor. SNI map and session ticketer are rebuilt. |

A change to *both* (e.g. swap to a new cert AND rewire routes in one editor save) is two independent reloads, in any order. Both swaps are atomic on their own.

## What reloads (config file)

Everything below is re-applied at the next request after the swap. In-flight requests continue with the snapshot they loaded — see [Snapshot consistency](#snapshot-consistency).

* `[server.listen_http]` / `[server.listen_https]` *(Phase 1.5)* — Zion binds the new address, spawns a fresh accept loop, and tells the previous listener to stop accepting. Connections already accepted by the old listener continue under the connection-limit semaphore until they finish. Bind failures (port in use, permission denied) log a structured WARN and **keep the existing listener** — a typo never strands the daemon. Caveats: see [Listener rebind caveats](#listener-rebind-caveats-phase-15).
* `[server.rate_limit_rps]`, `[server.rate_limit_window_secs]`
* `[server.trusted_proxies]`
* `[server.xff_mode]` (`append` | `rewrite` | `drop`)
* `[server.log_format]` is read at startup only — see [Out of scope](#out-of-scope).
* `[upstream.*]` URLs (host / port / scheme), connect timeout, keepalive
* Adding or removing `[upstream.*]` entries
* All `[[route]]` entries — adding, removing, repathing, switching upstream, switching mode (`standard` / `static_cache` / `sse_stream` / `websocket`), `internal_only`, `csp`, `auth_profile`, `cors`
* `[waf_profile.*]` — `mode`, body size limit, JSON depth and string-length limits, allowed content-types, `entropy_check`, `entropy_threshold`
* `[cache_profile.*]` — TTL and entry cap (the cache itself is not flushed; see [State that survives reloads](#state-that-survives-reloads))
* `[auth_profile.*]` (with `--features auth`)

## What reloads (certificate files)

Independent of `zion.toml`, the TLS watcher fires on changes to:

* `tls.cert_path` / `tls.key_path`
* Each `tls.sni[*].cert_path` / `key_path`

The `ServerConfig` is rebuilt from disk on the blocking thread pool (so file I/O does not stall the runtime), then atomic-swapped. ALPN, session tickets, 0-RTT settings, and mTLS verifier are reconstituted from the same `[tls]` section that is currently loaded.

## Listener rebind caveats (Phase 1.5)

The supervisor that reconciles `listen_*` to live listeners is conservative on purpose. Three behaviours worth pinning explicitly:

1. **Bind failure keeps the existing listener.** If the new address can't be bound — port already in use, no `CAP_NET_BIND_SERVICE` for `:80` / `:443`, malformed string, etc. — the supervisor logs a structured WARN and **does nothing else**. The previous listener keeps serving. There is no fallback, no retry loop; the next config reload (or a manual edit-and-save) gets another shot.

2. **Removing `listen_http` is a no-op.** If `[server.listen_http]` is dropped or set to an empty string in the new config, the supervisor leaves the existing HTTP listener in place. The intent is conservatism — losing the ACME challenge proxy or the 301-to-HTTPS redirect by mistake is a worse outcome than ignoring a possibly-deliberate removal. To stop accepting on `:80`, restart the process. (`listen_https` is treated the same way: an empty/missing value never tears down the existing primary listener.)

3. **`--features io-uring-accept`: HTTPS rebind is not supported.** The uring accept thread is bound to the listener's file descriptor at startup; rebinding would require tearing down and respawning the uring thread, which is out of scope for Phase 1.5. The supervisor logs `HTTPS rebind to X skipped: --features io-uring-accept is incompatible with rebind in Phase 1.5; restart required` and keeps the original listener. HTTP rebind continues to work in this build flavour. Operators who pivot HTTPS ports often should stay off the io_uring feature, or restart on each pivot.

These three rules answer "what happens if I…" deterministically; nothing on the listener supervisor side ever silently degrades availability.

## Out of scope (Phase 1 + Phase 1.5)

These do not hot-reload — they require a process restart:

* The path of `[tls]` cert/key files in `zion.toml` itself — the cert *content* hot-reloads (TLS watcher reads the current path on each reload), but if you point `cert_path` at a brand-new file, the TLS watcher is still subscribed to the old directory until restart.
* `[server.log_format]` — read once at startup by `logging::init`. Restart to switch between `text` and `json`.
* HTTP/3 listener (`--features http3`) — currently rebuilds on TLS reload only; config-side QUIC settings (incl. listen address) are not hot-applied.
* `[tls.acme]` (with `--features acme`) — the renewal task is spawned at boot from the initial config; changing email / domains / state_dir requires restart.
* `--features io-uring-accept`: HTTPS listener rebind. See caveat above.
* Build-time toggles: cargo features, allocator, target-cpu.

## Snapshot consistency

Each request snapshots the current config exactly once at the start of the pipeline (`AppState::cfg()`, ~5 ns: one Acquire load + one `Arc` refcount bump). The snapshot is held until the request finishes. As a consequence:

* If a reload swaps in a new config mid-flight, the request continues with the OLD config for routing, WAF, CORS, XFF policy, upstream selection, rate-limit settings.
* The next request loads the NEW config.
* HTTP/2 multiplexed streams that share one TCP connection each take their own snapshot per request, so the "everything in this connection sees one config" rule is per-request, not per-connection.
* WebSockets are different: the upgrade is one request that takes a snapshot, then the connection is bidirectionally piped for its lifetime. A WebSocket that started under config v1 stays bound to its v1 upstream for the whole session, even if v2 reroutes that path elsewhere.

The atomic swap uses [`arc_swap::ArcSwap`](https://docs.rs/arc-swap), the same primitive used for the TLS acceptor since long before Phase 1. Old snapshots are reclaimed by epoch-based GC once the last in-flight reader exits — no lock, no ref-count fence on the read path.

## Validation

Every reload runs the full `config::load_config` pipeline: TOML parse → reference resolution (each route's `upstream` / `waf_profile` / `cache_profile` / `auth_profile` must exist) → CIDR parsing for `trusted_proxies` → URL parsing for upstreams. If any check fails, the reload is rejected with a structured warning and the previous snapshot stays in place — Zion never serves traffic against an invalid config.

Sample logs:

```text
config_watcher: reload OK (gen 4 → 5)

config_watcher: reload REJECTED (Invalid TOML in zion.toml: TOML parse error
  at line 12, column 5 ...), keeping previous snapshot

config_watcher: reload REJECTED (route '/api/{*rest}' references unknown
  upstream 'apii'), keeping previous snapshot
```

A REJECTED reload does NOT bump `zion_config_generation`; that counter increments only on successful swaps, which makes "did my edit land?" a single-metric question:

```text
# Before the edit
$ curl -s http://127.0.0.1:80/_zion/snapshot.json | jq .config_generation
4

# After save:
$ curl -s http://127.0.0.1:80/_zion/snapshot.json | jq .config_generation
5    ← incremented = my edit was accepted
```

## State that survives reloads

* **L1 / L2 RAM cache.** Cached responses are keyed on full path + query, not on routes, so they survive a reload that re-paths or re-targets a route. *Caveat:* a cached entry under `/api/v1/...` continues to be served from RAM even if `/api/v1/{*rest}` is removed from the new config — but it will be served from cache only on a request that still routes there, which by definition cannot happen post-reload. So in practice the entry sits orphaned until its TTL expires or the L2 cap evicts it. It is never served against the new config.
* **Per-upstream health state.** `Arc<UpstreamHealth>` instances are reused across reloads for upstream URLs that are unchanged, so the prober's accumulated `healthy` flag and latency reading are preserved. New URLs start with the conservative "healthy + latency unknown" defaults; URLs removed from the new config drop their `Arc` once the last reader (the prober's current iteration) exits.
* **Per-IP rate-limit counters.** The `DashMap<IpAddr, RateEntry>` is part of `AppState`, not `ResolvedAppConfig`, so per-IP request counts survive reload. Only the *target* (`rate_limit_rps`, `rate_limit_window_secs`) hot-reloads.
* **Singleflight inflight map.** A request that is mid-fetch when the swap happens completes against the OLD upstream (per snapshot consistency above). Subsequent waiters for the same key are joined to that fetch.
* **HTTP client connection pool.** Pool entries are keyed on `(scheme, authority)`. If the new config keeps the same upstream URL, existing pooled connections are reused. If the URL changes, the new requests open new connections and the old idle ones reach `pool_idle_timeout` (30 s) and close.
* **TLS sessions** (16384-entry cache) survive cert reload as long as the cert chain accepted by the client is still valid post-swap.
* **`/healthz` / `/readyz` semantics.** Always return 200 OK on the inline fast-path; not affected by config state.

## Observability

Two surfaces report the reload state:

* Prometheus (`/metrics`):

  ```text
  # HELP zion_config_generation Successful zion.toml hot-reloads since process start.
  # TYPE zion_config_generation counter
  zion_config_generation 5
  ```

  Use this to alert on:
  - "no reload in N hours" (detect a stuck file watcher),
  - "reload storms" (detect a config tool that's emitting saves in a tight loop).

* Snapshot endpoint (`/_zion/snapshot.json`, internal-IP-only):

  ```json
  {
    "version": "0.1.7",
    "timestamp_ms": 1714425600000,
    "uptime_secs": 3712,
    "config_generation": 5,
    "platform": { ... },
    "metrics": { ... }
  }
  ```

  The `zion top` TUI surfaces this counter so an operator who edits `zion.toml` can confirm visually that the change landed.

* Daemon log lines (the structured-logging output goes to stderr, format selected by `[server.log_format]`):

  ```text
  config_watcher: watching /etc/zion/zion.toml
  config_watcher: reload OK (gen 0 → 1)
  config_watcher: reload REJECTED (...), keeping previous snapshot
  ```

## End-to-end check (operational)

A 60-second smoke procedure to verify hot-reload is wired in your deployment:

```bash
# 1. Read the current generation.
GEN_BEFORE=$(curl -s http://127.0.0.1:80/_zion/snapshot.json | jq .config_generation)

# 2. Make any innocuous edit (e.g. tweak rate_limit_rps to its current
#    value, or add a comment). Save.

# 3. Wait 3 seconds (2 s debounce + buffer).
sleep 3

# 4. Read again.
GEN_AFTER=$(curl -s http://127.0.0.1:80/_zion/snapshot.json | jq .config_generation)

# 5. Confirm.
[ "$GEN_AFTER" -gt "$GEN_BEFORE" ] && echo "OK: reload landed ($GEN_BEFORE → $GEN_AFTER)" \
                                  || echo "FAIL: counter unchanged"

# 6. (Optional) Sanity-check the REJECT path: write deliberately broken
#    TOML into the file; the same query above should leave the counter
#    UNCHANGED, and the daemon log should contain a "REJECTED" line.
```

## Atomicity at a glance

The diagram below traces the sequence of events for a single successful reload. T₀ is the editor save; T₃ is the moment a NEW request starts seeing the new snapshot.

```text
T₀  editor writes zion.toml
T₀+δ notify event reaches the watcher task
     (δ ≈ ms; OS-dependent — inotify on Linux, FSEvents on macOS)
T₀+2.0s   debounce window expires, parse begins on the blocking pool
T₂  parse + validate completes
     ├── on Err: log "REJECTED", DONE
     └── on Ok:
           T₂+ε  build new ResolvedAppConfig (matchit + AC lookup, sub-ms)
           T₃    state.config.store(Arc::new(new))
           T₃+0  CONFIG_GENERATION.fetch_add(1, Release)
           T₃+0  log "reload OK (gen N → N+1)"
```

After T₃, every fresh `AppState::cfg()` returns the new snapshot. In-flight requests that already called `cfg()` before T₃ continue with the old one until they finish; old `Arc` is reclaimed when its refcount hits zero.

## Caveats

* If an editor saves via `mv tmp target`, the file is briefly missing between unlink and rename. macOS FSEvents and Linux inotify both deliver the events but the order varies. The 2-second debounce ensures a single coherent reload at the end of the burst.
* If `zion.toml` is on a network filesystem (NFS, SMB) that does not reliably emit FS events, the watcher will miss saves. Workarounds: keep the config on local disk and bind-mount, or fall back to a future admin-API push (out of scope for Phase 1).
* The watcher does not poll. If `notify` cannot subscribe (extremely tight container, exotic FS), a WARN is emitted at startup and reloads are unavailable until the next process restart — Zion does not silently degrade.
* The reload runs the parser on the blocking pool but the rebuild itself runs on the runtime. Aho-Corasick automaton construction is cached per-mode in a `OnceLock` (built at the FIRST request that hits each mode, not at reload), so reloads do not re-pay automaton build cost — only the first-ever request does.
