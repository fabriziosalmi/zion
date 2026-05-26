# ACME (Let's Encrypt auto-renewal)

Zion can obtain and renew certificates automatically over [ACME](https://datatracker.ietf.org/doc/html/rfc8555) (RFC 8555) using the embedded [instant-acme](https://docs.rs/instant-acme/) client. Build with the `acme` feature:

```sh
cargo build --release --features acme
```

## Configuration

```toml
[tls.acme]
email          = "ops@example.com"                 # account contact
domains        = ["example.com", "www.example.com"]
directory_url  = "https://acme-v02.api.letsencrypt.org/directory"
renew_before_days = 30                              # renew when the cert expires within N days
state_dir      = "/etc/zion/acme"                   # account key + issued certs
```

Zion serves the **HTTP-01** challenge in-memory (no disk) on the HTTP listener — the token path `/.well-known/acme-challenge/{token}` is answered straight from a shared map, so port 80 must be reachable by the ACME server. A background task checks expiry every 12 hours and renews when within `renew_before_days`, then hot-reloads TLS via `ArcSwap` with no connection drop.

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

### Failure modes (follow-up)

Three adversarial legs are tracked for a follow-up:

- **Nonce collision** (`PEBBLE_WFE_NONCEREJECT`) — needs **per-request** `badNonce` retry; instant-acme 0.8.x does not expose it, and an operation-level retry can't recover a high per-request rejection rate.
- **Key rollover** — fresh-account issuance after discarding `account.json`.
- **TTL-edge expiry** — short-validity issuance + assert renewal fires.

The happy-path leg already proved its worth: it surfaced a real ordering bug (HTTP-01 tokens were dropped before `poll_ready`, racing validation) that real Let's Encrypt masked with slower validation timing.

Revocation uses `RevocationReason::Unspecified` against the account that issued the cert (restored from `state_dir/account.json`); the same `revoke_cert` entry point lets an operator retire a compromised key out-of-band.
