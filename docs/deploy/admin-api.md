# Admin API

The admin API is the **programmatic counterpart to [hot-reload](/deploy/hot-reload)**: instead of editing `zion.toml` on disk and letting the file watcher pick it up, an orchestrator can `POST` a new config (or trigger a disk re-read) over HTTP and get back the new config generation synchronously. Same validation, same atomic swap, same in-flight-safe semantics — just a different trigger.

It is **off by default**. With no `[admin]` block, no listener is spawned: zero overhead, zero attack surface. It runs on a **dedicated, loopback-by-default listener**, physically separate from the public `:443`, so a routing accident on the data plane can never expose `/admin/*`.

## Enabling it

```toml
[admin]
listen = "127.0.0.1:9180"   # default — loopback only
auth = "internal-ip"        # default — see Authentication
rate_limit_rps = 10         # default — global req/s ceiling
write_token_env = "ZION_ADMIN_WRITE_TOKEN"     # required for writes — see Write token
# persist_push = false      # default — see Persisting a push
```

Every field has the default shown, so a bare `[admin]` block is enough to turn it on with safe defaults. The block is validated at load: `listen` must be a real socket address, `auth` must be `internal-ip` or `mtls`, `rate_limit_rps` must be `> 0`, and `auth = "internal-ip"` requires a **loopback** `listen` (`127.0.0.1`, `::1`): it trusts every private-range peer, and that peer can replace the running config, so a routable or container-published bind needs `auth = "mtls"`. A typo fails fast at startup, exactly like the rest of `zion.toml`.

## Endpoints

| Method | Path | Effect |
|---|---|---|
| `GET`  | `/admin/config` | Return the live runtime snapshot (the same JSON as [`/_zion/snapshot.json`](/deploy/observability) — config generation, upstream health, metrics). Read-only. |
| `POST` | `/admin/config` | Push a full new config body (TOML). Validate → atomic-swap → bump generation. |
| `POST` | `/admin/reload` | Re-read `zion.toml` from disk (skips the watcher's 2 s debounce). |
| `POST` | `/admin/revoke` | Deny a JWT by its `jti` until its expiry. Body `{"jti":"...","exp":<unix secs>}`; `exp` defaults to 24 h from now. See [token revocation](/config/auth#token-lifetime-and-revocation). |

Any other method/path returns `404`.

### Read the live config

```console
$ curl -s localhost:9180/admin/config | jq '{generation: .config_generation, upstreams}'
{
  "generation": 7,
  "upstreams": [ { "url": "http://127.0.0.1:9090", "healthy": true, "latency_us": 412 } ]
}
```

### Push a new config

The body is the **complete** `zion.toml` (not a patch), capped at **1 MiB**, UTF-8. It flows through the same `validate → rebuild → atomic-swap → notify` path as a file edit — including a full validation pass (real cert paths and all: a pushed config must be deployable, not just parseable).

```console
$ curl -sX POST --data-binary @zion.toml localhost:9180/admin/config
{"generation":8}
```

On rejection nothing swaps — the previous config keeps serving — and you get the diagnostic plus a `400`:

```console
$ curl -sX POST --data-binary 'not [ valid toml' localhost:9180/admin/config
{"error":"Invalid TOML in admin push: TOML parse error at line 1, column 5 ..."}
```

A rejected push also increments the `zion_admin_rejects_total` metric.

### Reload from disk

Equivalent to editing-and-saving the file, but synchronous and immediate (no 2 s debounce):

```console
$ curl -sX POST localhost:9180/admin/reload
{"generation":9}
```

The `generation` in every success response is the new value of the `config_generation` counter — the same one surfaced on `/_zion/snapshot.json` and in metrics — so a deploy can confirm its change landed.

## Write token

`auth` decides who may talk to the listener at all. Every **mutating** call (`POST /admin/config`, `/admin/reload`, `/admin/revoke`) must also carry `Authorization: Bearer <token>`, where the token is the value of the environment variable named by `write_token_env` (at least 32 bytes). `GET /admin/config` stays under `auth` alone, so a monitoring client can read without being able to change anything.

**Without `write_token_env`, writes are refused** (`403`, with a message naming the setting; a warning at startup): network position, or a client certificate, authorizes reading the config, never replacing it. Before 0.9.8 a write from any peer that passed `auth` (on the loopback default, any local process) was accepted.

```console
$ export ZION_ADMIN_WRITE_TOKEN="$(openssl rand -hex 32)"
$ curl -X POST -H "Authorization: Bearer $ZION_ADMIN_WRITE_TOKEN" http://127.0.0.1:9180/admin/reload
```

A write without the token, or with a wrong one, gets `401`, is counted in `zion_admin_rejects_total`, and leaves an `admin_access` audit record. If `write_token_env` names a variable that is unset, empty or shorter than 32 bytes, **the admin listener does not start** (logged as an error): silently accepting writes from every peer that passes `auth` would be the opposite of what was asked.

## Persisting a push

By default `POST /admin/config` changes the running config only; a restart, or the next file reload, goes back to what is in `zion.toml`. With `persist_push = true` a push that **validated and went live** is also written to `zion.toml` (atomically, keeping the file's mode). A rejected push never touches the file. If the write fails the response is `500` and says the config is live but not saved.

Turn it on only when the pushed config is meant to be the source of truth: a `zion.toml` that is generated or kept in git will be overwritten by whatever was last pushed.

## Authentication

| Mode | Behaviour |
|---|---|
| `internal-ip` (default) | Plain HTTP. The connection **peer** must be a loopback / private-range IP (the same gate as `/_zion/snapshot.json`). |
| `mtls` | TLS with a **required** client certificate chaining to `admin.client_ca_path`. A completed handshake **is** the authorization — only CA-signed clients ever reach the HTTP layer, so the peer's IP no longer matters and the listener can safely bind a routable interface. Requires `admin.client_ca_path` (validated at load), its own CA: the data-plane `tls.client_ca_path` is not used, so a client certificate issued to call the gateway does not open the admin API (before 0.9.8 it did). |

For `internal-ip`, authorization is checked on the **TCP connection peer**, never on a forwarded header — `X-Forwarded-For` and `X-Client-Cert-*` are deliberately **not trusted** (admin auth is not transitive through a proxy). For `mtls`, the client cert is verified by rustls against the configured CA during the handshake; a missing or untrusted cert drops the connection before any request is served.

### Enabling mTLS

```toml
[tls]
cert_path = "/etc/ssl/zion/server.crt"   # the admin listener reuses the daemon's server cert
key_path  = "/etc/ssl/zion/server.key"

[admin]
listen = "0.0.0.0:9180"   # safe to expose: the handshake is the gate
auth = "mtls"
client_ca_path = "/etc/ssl/zion/admin-ca.crt"   # CA that signs OPERATOR client certs
write_token_env = "ZION_ADMIN_WRITE_TOKEN"     # writes still need the token
```

```console
# A client cert signed by admin-ca is mandatory; without it the handshake fails.
$ curl --cert operator.crt --key operator.key -k https://zion-host:9180/admin/config
{"config_generation":7, ...}
```

::: warning
`internal-ip` is only accepted on a loopback bind (`127.0.0.1`, the default): it trusts every host in the loopback and private ranges, and inside a container a bridge SNATs every client to a private address. Configuring it with `0.0.0.0` or any routable address is a startup error. Reach the loopback listener over an SSH tunnel or a sidecar, or use `mtls` when the admin API must be reachable across the network.
:::

## Rate limiting

The listener enforces a **global** fixed-window limit of `rate_limit_rps` requests per second (default 10) across all admin requests. Over the limit returns `429`. It is defense-in-depth — the listener is loopback and single-tenant — that bounds the (relatively expensive) reload path against a runaway deploy loop or a misbehaving client. Requests that fail the auth gate are not counted, so a rejected flood can't starve a real operator's budget.

## Auditing

When [`[audit]`](/security/hardening) is enabled, every **write** (`POST /admin/config`, `POST /admin/reload`) emits one `config_reload` audit event into the tamper-evident log:

```json
{ "kind": "config_reload", "remote_ip": "127.0.0.1", "method": "POST",
  "path": "/admin/reload", "detail": "admin config reload accepted → generation 9" }
```

Rejected pushes are recorded too (`detail: "admin config push rejected: ..."`). Reads are not audited. A request rejected by the rate limiter or the auth gate never reaches the write path, so it produces no audit event.

## Metrics

| Metric | Meaning |
|---|---|
| `zion_admin_rejects_total` | Admin config pushes rejected (invalid TOML / failed validation). A non-zero, climbing value means a deploy pipeline is pushing configs the daemon won't accept. |
| `config_generation` | Current config generation (on `/_zion/snapshot.json`). Bumps once per accepted reload, from any source — file edit, push, or disk reload. |

## Security model in one breath

* **Off unless configured.** No `[admin]` ⇒ no listener.
* **Loopback by default**, on its own port, physically separate from `:443`.
* **Peer-IP authorization**, never a forwarded header.
* **Full validation** before swap — a bad push is a `400`, never a half-applied config.
* **Rate-limited and audited.**

## Relationship to hot-reload

The admin API and the [file watcher](/deploy/hot-reload) are two triggers for **one** reload engine. Everything the watcher reloads, a push reloads identically; everything that survives a file reload (cache entries, connection-limit semaphore, in-flight requests) survives a push. The only differences are the trigger (HTTP vs. file event) and the timing (synchronous, no debounce). Use the file watcher for hand edits and GitOps-style file sync; use the admin API when an orchestrator wants a synchronous acknowledgement that its config landed.
