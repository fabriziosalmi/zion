# Configuration Reference

Zion is configured via a single TOML file. Default path: `./zion.toml`. Override with `ZION_CONFIG` env var.

All configuration is validated at startup. Invalid config produces actionable error messages and exits immediately.

## `[server]`

| Key | Type | Default | Description |
|---|---|---|---|
| `listen_http` | string | **required** | HTTP bind address (e.g. `"0.0.0.0:80"`) |
| `listen_https` | string | **required** | HTTPS bind address (e.g. `"0.0.0.0:443"`) |
| `rate_limit_rps` | u32 | `0` (disabled) | Max requests per IP per window |
| `rate_limit_window_secs` | u64 | `1` | Rate limit window in seconds |
| `max_connections_per_ip` | u32? | none | Per-IP concurrent-connection cap, enforced at accept (before the TLS handshake) |
| `trusted_proxies` | string[] | `[]` | CIDRs whose inbound `X-Forwarded-For` is trusted for client-IP resolution |
| `xff_mode` | string | `"append"` | Outbound XFF policy: `"append"`, `"rewrite"` (strip inbound, emit one trusted entry), or `"drop"` |
| `log_format` | string | `"text"` | `"text"` or `"json"` (structured) |

## `[tls]`

| Key | Type | Default | Description |
|---|---|---|---|
| `cert_path` | string | **required** | Path to PEM certificate chain |
| `key_path` | string | **required** | Path to PEM private key |
| `hot_reload` | bool | `true` | Watch cert directory for changes |
| `min_version` | string | `"1.3"` | Minimum TLS version (`"1.2"` or `"1.3"`) |
| `alpn` | string[] | `["h2", "http/1.1"]` | ALPN protocol negotiation list |
| `sni` | SniCert[] | `[]` | Per-domain certificate mappings |
| `acme` | table | none | Automatic HTTPS via Let's Encrypt — see [ACME](./acme) |
| `client_ca_path` | string? | none | CA bundle used to verify client certs (mTLS) |
| `client_auth` | string | `"none"` | mTLS client-auth mode (`"none"` disables mTLS) |

## `[upstream.<name>]`

| Key | Type | Default | Description |
|---|---|---|---|
| `url` | string | `url` **or** `urls` required | Single upstream URL (e.g. `"http://127.0.0.1:8000"`) |
| `urls` | string[] | `[]` | Multiple upstream URLs (latency-routed); use instead of `url` |
| `connect_timeout_ms` | u64 | `3000` | TCP connect timeout in milliseconds |
| `keepalive` | usize | `64` | Max idle keepalive connections |
| `tls` | bool | `false` | Use HTTPS to connect to upstream |
| `client_cert_path` / `client_key_path` | string? | none | Client cert + key for mTLS from Zion to the upstream |

Legacy format `[upstreams]` (flat key-value map of name to URL) is also supported.

## `[waf_profile.<name>]`

| Key | Type | Default | Description |
|---|---|---|---|
| `mode` | string | `"balanced"` | Pattern set: `"balanced"` (~100, high-precision) or `"aggressive"` (~240, broad-recall) |
| `max_body_mb` | u64 | `10` | Maximum request body size in MB |
| `max_depth` | usize | `10` | Maximum JSON nesting depth |
| `max_string_len` | usize | `1048576` | Maximum JSON string length (bytes) |
| `deny_unknown_content_types` | bool | `true` | Reject content types not in allowed list |
| `allowed_content_types` | string[] | `["application/json", "multipart/form-data"]` | Permitted content types |
| `entropy_check` | bool | `true` | Enable the Shannon-entropy gate on JSON string values |
| `entropy_threshold` | f64 | `6.5` | Bits/byte above which a JSON string value is flagged |
| `streaming` | bool | `false` | Scan request bodies chunk-by-chunk as they stream (fail-fast on first hit) |

## `[cache_profile.<name>]`

| Key | Type | Default | Description |
|---|---|---|---|
| `mode` | string | `"memory"` | Cache mode (`"memory"` or `"none"`) |
| `max_entries` | usize | `10000` | Maximum cached entries; the LRU evicts at this cap. `0` caches nothing (every insert evicts first) — it is not "unlimited". |
| `ttl_seconds` | u64 | `3600` | Time-to-live in seconds (default: 1 hour — a header-less origin response must not be frozen for a year; RFC 9111 §4.2.2 heuristic freshness). |

## `[[route]]`

| Key | Type | Default | Description |
|---|---|---|---|
| `path` | string | **required** | URL path pattern (radix tree, supports `{*rest}`) |
| `upstream` | string | **required** | Name of upstream to forward to |
| `mode` | string | `"standard"` | `standard`, `sse_stream`, `static_cache`, `websocket` |
| `internal_only` | bool | `false` | Restrict to private/loopback IPs |
| `waf_profile` | string | none | Name of WAF profile to apply |
| `cache_profile` | string | none | Name of cache profile to apply |
| `waf` | bool | `false` | Legacy: enable WAF with defaults |
| `max_body_mb` | u64 | `10` | Legacy: override body limit when `waf = true` |

## `[[route]]` → `cors`

CORS is a **per-route** inline table (`cors = { … }` under `[[route]]`), not a
top-level `[cors]` section — see [CORS](./cors). Keys:

| Key | Type | Default | Description |
|---|---|---|---|
| `allowed_origins` | string[] | `[]` (disabled) | Allowed origins. `["*"]` for any. |
| `allowed_headers` | string[] | `["Content-Type", "Authorization", "X-Requested-With"]` | Additional allowed headers |
| `max_age` | u64 | `86400` | Pre-flight cache duration in seconds |

## Environment variables

| Variable | Description |
|---|---|
| `ZION_CONFIG` | Config file path (default: `./zion.toml`) |
