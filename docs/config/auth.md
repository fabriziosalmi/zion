# Authentication (JWT/OIDC)

::: tip Feature-gated
Build with `--features auth` to enable JWT/OIDC authentication.
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
| `secret` | string | — | HMAC shared secret literal (HS256/HS384/HS512). **Prefer `secret_env`.** |
| `secret_env` | string | — | Name of an env var holding the HMAC secret. Preferred over `secret`; wins when both are set. |
| `jwks_url` | string | — | JWKS endpoint URL (for RS256/ES256, auto-refreshed hourly) |
| `algorithm` | string | `HS256` | JWT algorithm. Auto-selects RS256 when `jwks_url` is set without `secret` |
| `issuer` | string | — | Expected `iss` claim (optional) |
| `audience` | string | — | Expected `aud` claim (optional) |
| `forward_claims` | bool | `true` | Inject `X-Auth-Subject` and `X-Auth-Email` headers to upstream |

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
on every request, but it has **no revocation or replay defense**: there is no
denylist, no OIDC introspection, and no `jti`/nonce replay check. A valid token
is accepted until it expires, and can be replayed any number of times within
its lifetime.

Consequences for operators:

- **Issue short-lived tokens.** The token lifetime is your effective revocation
  window — a leaked token cannot be invalidated before `exp`. Minutes, not days.
- A logout / key-compromise event cannot be enforced at the edge mid-lifetime;
  rotate the signing key (or JWKS) to invalidate outstanding tokens en masse.
- If per-token revocation matters for your deployment, terminate auth at a
  service that maintains a denylist / introspection endpoint, and use Zion's
  gate as defense in depth.

### JWKS refresh

- JWKS is fetched at startup and refreshed every **1 hour**
- On fetch failure, retries with **exponential backoff** (5s, 10s, 20s, ... up to 1h)
- HTTP client failure is retried indefinitely (never gives up permanently)
- Clock skew tolerance: **30 seconds** (leeway for distributed systems)

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
