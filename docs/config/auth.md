# Authentication (JWT/OIDC)

::: tip Feature-gated
Build with `--features auth` to enable JWT/OIDC authentication.
:::

Zion supports per-route JWT validation as an optional authentication gate. Tokens are validated before the request reaches the upstream, preventing unauthorized access at the edge.

## Configuration

### HMAC (Symmetric)

For internal microservices using shared secrets:

```toml
[auth_profile.internal]
secret = "your-hmac-secret-key"
algorithm = "HS256"
issuer = "auth.internal"
audience = "api.internal"
forward_claims = true
```

### OIDC (Asymmetric)

For external identity providers (Auth0, Keycloak, Okta):

```toml
[auth_profile.oidc]
jwks_url = "https://auth.example.com/.well-known/jwks.json"
algorithm = "RS256"
issuer = "https://auth.example.com/"
audience = "api.example.com"
forward_claims = true
```

### Route Assignment

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
| `secret` | string | — | HMAC shared secret (for HS256/HS384/HS512) |
| `jwks_url` | string | — | JWKS endpoint URL (for RS256/ES256, auto-refreshed hourly) |
| `algorithm` | string | `HS256` | JWT algorithm. Auto-selects RS256 when `jwks_url` is set without `secret` |
| `issuer` | string | — | Expected `iss` claim (optional) |
| `audience` | string | — | Expected `aud` claim (optional) |
| `forward_claims` | bool | `true` | Inject `X-Auth-Subject` and `X-Auth-Email` headers to upstream |

## Supported Algorithms

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

### Claim Forwarding

When `forward_claims = true`, decoded claims are injected as headers:

| Header | Claim | Description |
|--------|-------|-------------|
| `X-Auth-Subject` | `sub` | User ID / subject |
| `X-Auth-Email` | `email` | User email (if present in token) |

### JWKS Refresh

- JWKS is fetched at startup and refreshed every **1 hour**
- On fetch failure, retries with **exponential backoff** (5s, 10s, 20s, ... up to 1h)
- HTTP client failure is retried indefinitely (never gives up permanently)
- Clock skew tolerance: **30 seconds** (leeway for distributed systems)

## Bearer Token Extraction

The `Authorization` header is parsed case-insensitively per [RFC 6750 Section 2.1](https://datatracker.ietf.org/doc/html/rfc6750#section-2.1):

```
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Authorization: bearer eyJhbGciOiJSUzI1NiJ9...    # also accepted
Authorization: BEARER eyJhbGciOiJSUzI1NiJ9...    # also accepted
```

## Build

```bash
cargo build --release --features auth
```
