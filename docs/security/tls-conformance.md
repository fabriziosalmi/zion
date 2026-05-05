# TLS conformance

Plan + recipes for proving Zion's TLS implementation behaves correctly
against published test vectors.

Zion does not implement TLS itself — it consumes
[rustls](https://github.com/rustls/rustls) (record layer + handshake)
on top of [aws-lc-rs](https://github.com/aws/aws-lc-rs) (primitives).
Both projects ship their own conformance suites. This document captures:

- Which suites exist.
- How to run them against a Zion build.
- What's already implicitly covered by the upstream CI.
- The gaps Zion's own integration tests must fill.

## Inherited coverage (upstream CI)

| Suite | Covers | Where |
|---|---|---|
| [rustls-bogo-shim](https://github.com/rustls/rustls/tree/main/rustls-bogo-shim) | BoringSSL's BoGo TLS test suite (~600 cases) | rustls CI on every commit |
| `rustls-internal-test-vectors` | RFC 8446 / TLS 1.3 conformance vectors | rustls CI |
| AWS-LC ACVP / CAVP | NIST CAVP test vectors for AES, SHA, HMAC, ECDSA, etc. | aws-lc CI; published as part of FIPS validation |
| webpki-roots | Mozilla CA bundle integrity | webpki-roots CI |

A green Zion build with a passing rustls/aws-lc-rs inherits all of the
above. The version locks in `Cargo.lock` are the integrity link — pin
upgrades go through `cargo audit` + manual review per
[deny.toml](../../deny.toml).

## Running BoGo against a Zion build (operator recipe)

To exercise Zion's *integration* with rustls (rather than rustls in
isolation), run the BoGo shim against a live daemon on `:443`:

```bash
# 1. Start Zion with a self-signed cert.
cargo build --release --features init,acme
./target/release/zion init -y --hostname conformance.test.local
ZION_CONFIG=zion.toml ./target/release/zion &
ZION_PID=$!
trap "kill $ZION_PID" EXIT

# 2. Clone the rustls BoGo runner.
git clone --depth=1 https://github.com/rustls/rustls
cd rustls/rustls-bogo-shim
cargo build --release

# 3. Point BoGo at Zion's HTTPS port.
RUSTLS_BOGO_TARGET=127.0.0.1:443 cargo run --release -- \
    -shim-path ../../target/release/zion \
    -test-error-map ./testerrormap.json \
    -allow-unimplemented
```

Expected: every case the upstream rustls passes also passes against
Zion. Failures are *integration* defects (something Zion configured
overrode a rustls default in a way that broke conformance) and become
P1 issues.

## Internal smoke + soak tests

Zion's [`tests/integration.rs`](../../tests/integration.rs) runs a
small subset of TLS behaviours end-to-end against a live daemon. The
suite is `--ignored` by default (it requires a backend running). The
relevant cases:

| Test | RFC reference |
|---|---|
| `tls_handshake_succeeds_with_default_cert` | RFC 8446 §4.1 |
| `early_data_replayed_state_changing_method_returns_425` | RFC 8470 §5.2 |
| `client_cert_required_when_optional_provided_accepts` | RFC 8446 §4.4.2 |
| `mtls_fingerprint_header_emitted` | Zion-specific |

Run with:

```bash
cd benchmarks/backend && cargo run --release &
ZION_CONFIG=tests/zion-test.toml ./target/release/zion &
cargo test --test integration -- --ignored --test-threads=1
```

## External validation

For deployments that need third-party attestation:

1. **SSL Labs** ([ssllabs.com/ssltest/](https://www.ssllabs.com/ssltest/))
   — public-facing scan. Zion targets an A+ grade with the default
   `[tls]` block. We track the canonical-deploy result in the release
   notes for each minor version.
2. **Mozilla Observatory** ([observatory.mozilla.org](https://observatory.mozilla.org/))
   — checks security headers in addition to TLS. The
   `inject_security_headers` chain delivers HSTS preload, CSP nonce
   recipe (per-route), Referrer-Policy, Permissions-Policy.
3. **testssl.sh** ([testssl.sh](https://testssl.sh/)) — for
   air-gapped / self-hosted scans where SSL Labs isn't reachable.
4. **NIST FIPS validation transcript** — a `--features fips` build's
   power-on self-test output is the per-process attestation; the
   underlying module's NIST certificate (Cert. #4759) is the authority.

## Gaps and roadmap

| Gap | Status |
|---|---|
| Run BoGo as a CI job (build-only) | Tracked in [docs/perf/roadmap.md](../perf/roadmap.md); needs a Linux runner with the BoGo build pre-warmed |
| Wycheproof crypto vectors for HMAC/ECDSA | Inherited from aws-lc-rs CI; not re-run inside Zion |
| ACME staging-environment soak | Manual today — `--features acme` against Let's Encrypt staging |
| Public-internet TLS scan in release pipeline | Out of scope — operator-side concern |

## References

- [RFC 8446 — TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [RFC 8470 — Using Early Data in HTTP](https://datatracker.ietf.org/doc/html/rfc8470)
- [BoGo test suite](https://boringssl.googlesource.com/boringssl/+/master/ssl/test/)
- [rustls test infrastructure](https://github.com/rustls/rustls/tree/main/rustls-bogo-shim)
- [NIST CMVP](https://csrc.nist.gov/projects/cryptographic-module-validation-program)
