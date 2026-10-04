# Authentication (JWT/OIDC)

::: tip Feature-gated
The official release binaries and container include it (since 0.9.8, `--features dist`).
A source build needs `--features auth`. A build **without** it refuses to start on a
config whose routes set `auth_profile`, rather than serve them unauthenticated.
:::

Zion supports per-route JWT validation as an optional authentication gate. Tokens are validated before the request reaches the upstream, preventing unauthorized access at the edge.

## Configuration

### HMAC (symmetric)

For internal microservices using shared secrets:

```toml
[auth_profile.internal]
# Prefer secret_env over a literal `secret` — it keeps the signing key out of
# zion.toml (and out of version control). It names an environment variable:
secret_env = "ZION_AUTH_INTERNAL_SECRET"
algorithm = "HS256"
issuer = "auth.internal"
audience = "api.internal"
forward_claims = true
```

::: warning Keep the HMAC secret out of the config file
A literal `secret` puts a live signing key in `zion.toml` — anyone who can read
the file can forge valid tokens. Use `secret_env` (the name of an env var
holding the secret); it wins over `secret` when both are set, and a
named-but-missing/empty env var fails startup rather than silently continuing.
:::

### OIDC (asymmetric)

For external identity providers (Auth0, Keycloak, Okta):

```toml
[auth_profile.oidc]
jwks_url = "https://auth.example.com/.well-known/jwks.json"
algorithm = "RS256"
issuer = "https://auth.example.com/"
audience = "api.example.com"
forward_claims = true
```

### Route assignment

```toml
[[route]]
path = "/api/protected/{*rest}"
upstream = "backend"
auth_profile = "oidc"
waf = true
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `secret` | string | — | HMAC shared secret literal (HS256/HS384/HS512). **Deprecated: use `secret_env`.** Zion warns at boot when it is set. It is redacted from debug output and wiped from memory when the config is dropped. |
| `secret_env` | string | — | Name of an env var holding the HMAC secret. Preferred over `secret`; wins when both are set. The secret must be at least as long as the hash (RFC 7518 §3.2): 32 bytes for HS256, 48 for HS384, 64 for HS512; a shorter one is refused at boot and on reload (`openssl rand -base64 48`). |
| `previous_secret_env` | string | — | Name of an env var holding the previous HMAC secret, accepted next to the current one during a [key rotation](#rotating-the-signing-key). Remove it when the old tokens have expired. |
| `jwks_url` | string | — | JWKS endpoint URL (for RS256/ES256, auto-refreshed hourly). Must be `https://` (plain `http://` only to a loopback address); anything else is refused. |
| `algorithm` | string | `HS256` | JWT algorithm. Auto-selects RS256 when `jwks_url` is set without `secret` |
| `issuer` | string | — | Expected `iss` claim (optional) |
| `audience` | string | — | Expected `aud` claim (optional) |
| `forward_claims` | bool | `true` | Inject `X-Auth-Subject` and `X-Auth-Email` headers to upstream |
| `leeway_secs` | integer | `30` | Clock-skew tolerance applied to `exp`/`nbf`. `0` is allowed; above `300` is rejected. |
| `max_token_lifetime_secs` | integer | — | Reject tokens whose `exp` is further in the future than this (plus `leeway_secs`). Unset = no cap. See [Token lifetime and revocation](#token-lifetime-and-revocation). `0` = no cap, on purpose. **Unset becomes `86400` in the next minor release**; until then tokens beyond 24 h are accepted, counted (`zion_auth_long_lived_tokens_total`) and warned about. |

## Supported algorithms

| Algorithm | Type | Use Case |
|-----------|------|----------|
| HS256, HS384, HS512 | Symmetric (HMAC) | Internal microservices |
| RS256, RS384, RS512 | Asymmetric (RSA) | OIDC providers (Auth0, Keycloak) |
| ES256, ES384 | Asymmetric (ECDSA) | Modern OIDC providers |

## Behavior

1. **Missing `Authorization` header**: Returns `401 Unauthorized`
2. **Invalid/malformed token**: Returns `403 Forbidden`
3. **Expired token**: Returns `401 Unauthorized` with body `token expired`
4. **Valid token**: Request proceeds to upstream with optional claim headers

### Claim forwarding

When `forward_claims = true`, decoded claims are injected as headers:

| Header | Claim | Description |
|--------|-------|-------------|
| `X-Auth-Subject` | `sub` | User ID / subject |
| `X-Auth-Email` | `email` | User email (if present in token) |

These headers are **reserved**: Zion strips any inbound `X-Auth-Subject` /
`X-Auth-Email` from the client on every request (regardless of the auth
feature or whether a route has an auth profile) before the gate re-injects the
verified values, so an upstream can trust them as authenticated. A client
cannot forge them.

## Token lifetime and revocation

Zion validates a token's **signature, expiry (`exp`), and not-before (`nbf`)**
on every request. It has **no replay defense** (a valid token can be presented any
number of times within its lifetime) and no OIDC introspection. It does have a
small per-instance **revocation list** keyed on the `jti` claim, described below.

### Revoking a token

`POST /admin/revoke` on the [admin API](/deploy/admin-api) with
`{"jti":"<token id>","exp":<the token's exp, unix seconds>}` denies that token id
until `exp`; a request carrying it gets `403`. Limits you should know about:

- Only a token that **carries a `jti`** can be revoked. Issue one on every token.
- The list is **per instance**: with several Zion instances you revoke on each. It
  is capped at 100 000 live entries.
- It is **in memory unless `[admin] revocations_path` is set**. Without it a restart
  makes every revoked token valid again until it expires. With it each revocation is
  written to that file before the API answers, and read back at boot (expired
  entries are dropped). If the file exists and cannot be read, zion refuses to start
  rather than start with nothing revoked.
- It is a stop-gap for a leaked token, not a session system. For revocation that
  must span a fleet, keep tokens short-lived and rotate the key.

### Rotating the signing key

Changing `secret_env` to a new key makes every outstanding token invalid at the
reload. To rotate without that outage, keep the old key readable for a while:

```toml
[auth_profile.internal]
secret_env = "ZION_AUTH_SECRET"            # the new key: what you sign with from now on
previous_secret_env = "ZION_AUTH_SECRET_OLD"  # the old key: still accepted
```

1. Put the new key in `ZION_AUTH_SECRET` and the old one in `ZION_AUTH_SECRET_OLD`,
   set `previous_secret_env`, restart or reload. Tokens signed with either verify.
2. Start signing with the new key.
3. When the longest-lived old token has expired, remove `previous_secret_env`.

A token is checked against the previous key only when the current one rejects its
signature; expiry, issuer and audience are checked the same either way. The
previous key must be set and as long as the current one (config validation), and
the setting only makes sense with an HMAC secret.

Consequences for operators:

- **Issue short-lived tokens.** The token lifetime is your effective revocation
  window — a leaked token cannot be invalidated before `exp`. Minutes, not days.
  Set `max_token_lifetime_secs` to the longest lifetime you actually issue (for
  example `900`) and Zion rejects any token whose `exp` is further out, so a
  mis-issued or forged-by-a-leaked-key token with a far-future `exp` is refused
  instead of living for years. `0` means "no cap", said on purpose.
- **The default is changing.** Today a profile without the setting has no cap.
  From the next minor release the default is `86400` (24 h) and a token further
  out is refused. Until then such a token is accepted, counted in
  `zion_auth_long_lived_tokens_total`, and warned about in the log (once a minute
  at most), and zion warns at boot for every profile without the setting. If the
  counter stays at zero, the change will not affect you; otherwise set the value
  you need, or `0`.
- `aud` may be a single string or an array (OIDC providers commonly send an
  array); the profile's `audience` must appear in it.
- A logout / key-compromise event cannot be enforced at the edge mid-lifetime;
  rotate the signing key (or JWKS) to invalidate outstanding tokens en masse.
- If revocation must be durable or fleet-wide, terminate auth at a service that
  maintains a denylist / introspection endpoint, and use Zion's gate as defense in
  depth.

### JWKS refresh

- JWKS is fetched at startup and refreshed every **1 hour**
- On fetch failure, retries with **exponential backoff** (5s, 10s, 20s, ... up to 1h)
- HTTP client failure is retried indefinitely (never gives up permanently)
- Clock skew tolerance: **30 seconds** by default (`leeway_secs`, at most 300)

## Bearer token extraction

The `Authorization` header is parsed case-insensitively per [RFC 6750 Section 2.1](https://datatracker.ietf.org/doc/html/rfc6750#section-2.1):

```http
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Authorization: bearer eyJhbGciOiJSUzI1NiJ9...    # also accepted
Authorization: BEARER eyJhbGciOiJSUzI1NiJ9...    # also accepted
```

## Build

```bash
cargo build --release --features auth
```
