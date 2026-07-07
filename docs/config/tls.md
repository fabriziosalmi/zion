# TLS & SNI

Zion terminates TLS using [rustls](https://github.com/rustls/rustls) with the aws-lc-rs cryptography backend. No OpenSSL dependency.

## Basic Configuration

```toml
[tls]
cert_path = "/etc/ssl/zion/tls.crt"
key_path = "/etc/ssl/zion/tls.key"
```

Both files must be PEM-encoded. The certificate file should contain the full chain (leaf + intermediates).

## TLS Version Control

```toml
[tls]
min_version = "1.3"   # Default: TLS 1.3 only (fastest handshake)
# min_version = "1.2" # Allow TLS 1.2 + 1.3
```

TLS 1.3 is the default because it has a shorter handshake (1-RTT vs 2-RTT) and mandatory forward secrecy. Set `"1.2"` only if you need to support older clients.

## ALPN Negotiation

```toml
[tls]
alpn = ["h2", "http/1.1"]   # Default: HTTP/2 preferred
# alpn = ["http/1.1"]       # HTTP/1.1 only
```

## Multi-Domain SNI

For multiple domains on the same IP, add `[[tls.sni]]` entries:

```toml
[tls]
cert_path = "/etc/ssl/zion/default.crt"
key_path = "/etc/ssl/zion/default.key"

[[tls.sni]]
server_name = "api.example.com"
cert_path = "/etc/ssl/zion/api.crt"
key_path = "/etc/ssl/zion/api.key"

[[tls.sni]]
server_name = "app.example.com"
cert_path = "/etc/ssl/zion/app.crt"
key_path = "/etc/ssl/zion/app.key"
```

Zion selects the resolver mode at boot:

| Mode | Condition | Overhead |
|---|---|---|
| SingleCertResolver | No `[[tls.sni]]` entries | ~2ns (Arc clone) |
| SniResolver | 1+ `[[tls.sni]]` entries | ~15ns (FNV hash + thread-local cache) |

If the client's SNI does not match any entry, the default certificate is used as fallback.

## Hot-Reload

```toml
[tls]
hot_reload = true   # Default: enabled
```

When enabled, Zion watches the certificate directory using `notify` (inotify on Linux, FSEvents on macOS). On file change:

1. 2-second debounce (avoids partial writes)
2. Load and validate new certificates
3. Build new `ServerConfig` with all certs (default + SNI)
4. Atomic swap via `ArcSwap` -- new connections get new certs
5. In-flight connections continue with old certs until they close

If the reload fails (bad cert, missing file), the previous configuration is retained and an error is logged. No downtime in any case.

## Session Resumption & 0-RTT

Zion configures aggressive session resumption by default:

- **Session cache**: 16,384 entries (vs rustls default of 256)
- **Session tickets**: Enabled via `Ticketer` — stateless resumption, no server-side storage
- **0-RTT early data**: Enabled (`max_early_data_size = 16384`) with **method gating** — see below
- **Server cipher order**: Enforced — server selects the strongest cipher
- **Half-RTT data**: Enabled — server sends data before client `Finished` message on resumed sessions

Each cached/ticketed session avoids a full ECDHE key exchange (~1ms saved per resumed handshake).

### 0-RTT Replay Protection

TLS 1.3 0-RTT allows clients to send data in the first flight on resumed connections, saving ~35% handshake latency. However, early data can be **replayed** by network attackers.

Zion mitigates this with **method gating** (RFC 8470):

| Method | 0-RTT Allowed | Rationale |
|---|---|---|
| `GET`, `HEAD` | Yes | Idempotent — safe to replay |
| `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS` | No (425) | Non-idempotent — replay could duplicate side effects |

When a non-idempotent request arrives on early data, Zion responds with `425 Too Early`. Well-behaved clients (all modern browsers) retry the request after the handshake completes.

The early data flag is consumed via an `AtomicBool` on first request per connection — only the first request can be 0-RTT, all subsequent requests on the same connection proceed normally.

## TLS Handshake Timeout

TLS handshakes are limited to 10 seconds. Connections that do not complete the handshake within this window are dropped. Failed handshakes are counted in `zion_tls_handshake_errors`.

## ACME auto-renewal

> The full guide — first-boot issuance, the bootstrap cert, HTTP-01, renewal and
> revocation — lives on the dedicated [Automatic HTTPS (ACME)](./acme) page. This
> section is a quick reference for the `[tls.acme]` block.
>
> Requires build with `cargo build --release --features acme`.

Zion can automatically obtain and renew TLS certificates from Let's Encrypt (or any ACME-compatible CA).

```toml
[tls.acme]
email = "ops@example.com"
domains = ["example.com", "www.example.com"]
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
state_dir = "/var/lib/zion/acme"
renew_before_days = 30
```

| Field | Default | Description |
|---|---|---|
| `email` | *(required)* | Contact email for Let's Encrypt notifications |
| `domains` | *(required)* | List of domains to request certificates for |
| `directory_url` | LE production | ACME directory URL |
| `state_dir` | `/var/lib/zion/acme` | Directory for account credentials and cert/state persistence |
| `renew_before_days` | `30` | Start renewal this many days before expiry |

### How It Works

1. Background task checks certificate expiry every 12 hours
2. If cert expires within `renew_before_days`, initiates ACME order
3. Serves HTTP-01 challenge token on port 80 (in-memory, no disk files)
4. Receives signed certificate from CA
5. Writes cert + key to `cert_path` / `key_path`
6. Hot-reloads TLS via `ArcSwap` — zero downtime

### Account Persistence

ACME account credentials are saved to `state_dir/account.json` on first run. Subsequent runs reuse the existing account.

### Staging / Testing

For testing, use the Let's Encrypt staging environment:

```toml
directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
```

### Fallback: renew.sh

If compiled without `--features acme`, Zion falls back to executing `state_dir/renew.sh` (if it exists). This allows external certificate management tools (e.g., certbot) to handle renewal. The script must:

- Be a regular file (not a symlink)
- Not be world-writable
- Exit 0 on success
