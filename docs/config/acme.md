# Automatic HTTPS (ACME / Let's Encrypt)

Zion obtains and renews certificates automatically over [ACME](https://datatracker.ietf.org/doc/html/rfc8555) (RFC 8555) using the embedded [instant-acme](https://docs.rs/instant-acme/) client. **The release binary and official container already include it** (the `dist` bundle); a local `cargo build` needs the feature:

```sh
cargo build --release --features acme   # or --features dist (acme + init)
```

## The fast path: `zion init`

On a public domain, the wizard sets everything up for you — a `[tls.acme]` block plus a short-lived bootstrap cert so `:443` binds while ACME provisions the real one on first boot:

```sh
zion init --hostname app.example.com --email ops@example.com
ZION_CONFIG=zion.toml zion
```

## Configuration

```toml
[tls.acme]
email          = "ops@example.com"                 # account contact
domains        = ["example.com", "www.example.com"]
directory_url  = "https://acme-v02.api.letsencrypt.org/directory"
renew_before_days = 30                              # renew when the cert expires within N days
state_dir      = "/var/lib/zion/acme"               # runtime-written: account key + issued certs
```

Zion serves the **HTTP-01** challenge in-memory (no disk) on the HTTP listener — the token path `/.well-known/acme-challenge/{token}` is answered straight from a shared map, so port 80 must be reachable by the ACME server. (You do **not** need a route for it.) If an *external* ACME client (certbot, an upstream that runs its own ACME) must answer the challenge instead, Zion forwards an unmatched `/.well-known/acme-challenge/*` request on port 80 to the matching route's upstream, with `X-Auth-*` stripped. It does so only for a route with nothing to bypass: **a route with `auth_profile`, `internal_only`, or `mode = "static"` is never used for this** (the request is redirected to HTTPS instead, where the normal pipeline applies). Serve the challenge from a public route, e.g. `path = "/.well-known/acme-challenge/{*token}"`. A background task checks expiry every 12 hours and renews when within `renew_before_days`, then hot-reloads TLS via `ArcSwap` with no connection drop.

`cert_path`/`key_path` in `[tls]` still hold the certificate — ACME writes the obtained cert there. On a fresh host they need a bootstrap cert so the listener can bind; `zion init` generates a 1-day self-signed one that ACME immediately replaces. If you hand-write `[tls.acme]` with your own long-lived bootstrap cert, first issuance waits until that cert is within the renewal window — use `zion init` or a short-lived bootstrap cert to get a real cert immediately.

`state_dir` is written at runtime by the (non-root) process, so it lives under `/var/lib/zion`, not `/etc`; the official container pre-creates it writable.

## Observability

Two counters track the certificate lifecycle (Prometheus `/metrics`):

| Metric | Meaning |
|---|---|
| `zion_acme_renewals_total` | Certificates successfully issued or renewed |
| `zion_acme_renewal_failures_total` | Renewal attempts that failed (any stage) |

Alert on a rising `zion_acme_renewal_failures_total` or a flat `zion_acme_renewals_total` as expiry approaches.

## CI soak (issue #59)

The [`acme-soak`](https://github.com/fabriziosalmi/zion/blob/master/.github/workflows/acme-soak.yml) workflow exercises the full **issue → renew → revoke** cycle weekly (and on demand via `workflow_dispatch`) against a hermetic [Pebble](https://github.com/letsencrypt/pebble) test CA — Let's Encrypt's official test server — with DNS mocked by `pebble-challtestsrv`. No real Let's Encrypt, no external DNS, no rate limits.

The soak is driven by a hidden subcommand:

```sh
ZION_ACME_TEST_DIRECTORY=https://pebble:14000/dir \
ZION_ACME_TEST_DOMAIN=acme-soak.test \
ZION_ACME_TEST_HTTP_PORT=5002 \
zion acme-soak        # exits 0 on PASS, non-zero on FAIL
```

`acme-soak` runs zion's *real* `renew_once` / `revoke_cert` paths, so a regression in the production ACME flow fails the soak. It also asserts the lifecycle counters move (`zion_acme_renewals_total` ≥ 2 across issue + renew).

### Failure-mode legs

`ZION_ACME_SOAK_MODE` selects the leg (`happy` is the default). CI runs all four, each against its own Pebble:

- **`key-rollover`**: fresh-account issuance after discarding `account.json`.
- **`ttl-edge`**: issue a real certificate and assert the renewal trigger fires exactly at the `renew_before_days` edge, then drive that renewal.
- **`nonce-collision`**: Pebble rejects 20% of the anti-replay nonces (`PEBBLE_WFE_NONCEREJECT`); issue → five renewals → revoke must still complete. instant-acme 0.8.5 retries **each request** on `badNonce` (RFC 8555 §6.5, up to 3 attempts); the soak allows a few whole-operation attempts for the rare request that exhausts them. The workflow also proves the injection is real: at 100% rejection issuance must fail with `badNonce` after exactly 3 attempts.

The happy-path leg already proved its worth: it surfaced a real ordering bug (HTTP-01 tokens were dropped before `poll_ready`, racing validation) that real Let's Encrypt masked with slower validation timing.

Revocation uses `RevocationReason::Unspecified` against the account that issued the cert (restored from `state_dir/account.json`); the same `revoke_cert` entry point lets an operator retire a compromised key out-of-band.
