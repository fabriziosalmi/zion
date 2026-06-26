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

## Running BoGo against the rustls version Zion ships

> **BoGo does not connect to a TLS server.** Its Go runner drives a
> *shim* binary as a subprocess per test case, feeding the per-test
> handshake configuration over a CLI protocol. Zion is not a BoGo shim,
> so you cannot point BoGo at Zion's `:443`. rustls ships the shim (in
> its `bogo/` directory); the meaningful, version-locked check is to
> build that shim from the **rustls release Zion pins** and run the
> suite. A green run proves the exact `rustls` + `aws-lc-rs` versions in
> Zion's `Cargo.lock` are BoGo-conformant.

This is automated in CI — see
[`.github/workflows/tls-conformance.yml`](../../.github/workflows/tls-conformance.yml)
(`tls-conformance`): weekly + on any PR touching `src/tls.rs` /
`Cargo.toml` / `Cargo.lock`, plus `gh workflow run tls-conformance.yml`.

The operator recipe it encodes:

```bash
# 1. Read the rustls version Zion pins.
RUSTLS_VER=$(awk '/^name = "rustls"$/{getline; gsub(/[" ]/,"",$3); print $3; exit}' Cargo.lock)

# 2. Check out rustls at that release (tags are `v/<version>`).
git clone --depth=1 --branch "v/$RUSTLS_VER" https://github.com/rustls/rustls
cd rustls

# 3. (optional) Align aws-lc-rs with Zion's exact pin.
cargo update -p aws-lc-rs --precise "$(awk '/^name = "aws-lc-rs"$/{getline; gsub(/[" ]/,"",$3); print $3; exit}' ../Cargo.lock)" || true

# 4. Run the suite (needs Go + a C preprocessor; `runme` builds the
#    shim and the pinned BoringSSL runner). On Linux `runme` exits
#    non-zero on any unexpected failure.
cd bogo && BOGO_SHIM_PROVIDER=aws-lc-rs ./runme
```

Expected: the same pass rate upstream rustls reports for that release.
A failure here means the pinned `rustls`/`aws-lc-rs` combination
diverged from upstream BoGo expectations — i.e. a dependency bump
regressed conformance, caught on the PR that bumps it.

> Testing Zion's *own* `ServerConfig` integration (rather than rustls in
> isolation) would require Zion to expose a BoGo-shim-compatible mode —
> tracked as a possible follow-up. Since Zion builds on rustls's
> defaults, the version-pinned suite above is the high-value coverage.

## Internal unit tests (CI-run)

Zion's TLS-relevant *decisions* are pinned by pure-function unit tests that run
in CI on every push (`cargo test`) — not by an external harness. Because they
test the decision logic directly, a refactor that silently weakened the version
floor or re-enabled non-idempotent 0-RTT replay fails CI.

| Test (`src/…`) | What it pins | RFC |
|---|---|---|
| `tls::protocol_versions_fail_safe_to_tls13_only`, `…_floor_opens_only_on_exact_1_2` | the version floor is fail-safe: only the literal `"1.2"` opens TLS 1.2, any other value (typo, empty, `"1.3"`) collapses to 1.3-only | RFC 8446 |
| `dispatch::early_data_rejects_state_changing_methods`, `early_data_allows_safe_methods`, `no_early_data_never_rejects` | 0-RTT early data carries only GET/HEAD; a state-changing method in early data gets **425 Too Early** | RFC 8470 §5.2 |
| `tls::fingerprint_format_is_sha256_prefix_plus_64_hex`, `…_matches_known_sha256_vector`, `…_is_deterministic_for_same_input`, `…_diffuses_single_bit_flips` | the mTLS client-cert fingerprint wire format `sha256:<64-hex>` | — |

## End-to-end behaviours (manual / e2e — not CI-gated)

Full-stack TLS behaviours are exercised by the `--ignored` integration suite
([`tests/integration.rs`](../../tests/integration.rs), which needs a running
daemon + backend) and the e2e rig — **not** by CI unit tests:

- **Handshake with the default cert** — every integration case connects to
  Zion over TLS, so a broken default-cert handshake fails the whole suite.
- **mTLS client-cert *header emission*** (injecting `sha256:<hex>` into the
  upstream request) — the fingerprint *format* is unit-tested (above); the
  end-to-end emission on an mTLS route is **not yet covered by an automated
  test** (tracked in Gaps below).
- **ALPN negotiation** (h2/http1.1) — cross-checked by the baseline harness
  (`benchmarks/baseline/`, h2load/wrk legs).

```bash
cd benchmarks/backend && go run test-server.go &
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
| Run BoGo as a CI job | **Done** (#56) — [`tls-conformance.yml`](../../.github/workflows/tls-conformance.yml) runs the suite against the rustls release Zion pins, weekly + on dependency-pin PRs |
| BoGo against Zion's own `ServerConfig` (shim mode) | Possible follow-up — needs a `zion`-side BoGo shim; low marginal value while Zion uses rustls defaults |
| mTLS fingerprint header-emission e2e test | Gap — the fingerprint *format* is unit-tested; the end-to-end injection of `X-Client-Cert-Fingerprint` on an mTLS route needs a client-cert fixture + an mTLS route in `tests/zion-test.toml` |
| Wycheproof crypto vectors for HMAC/ECDSA | Inherited from aws-lc-rs CI; not re-run inside Zion |
| ACME staging-environment soak | Manual today — `--features acme` against Let's Encrypt staging |
| Public-internet TLS scan in release pipeline | Out of scope — operator-side concern |

## References

- [RFC 8446 — TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [RFC 8470 — Using Early Data in HTTP](https://datatracker.ietf.org/doc/html/rfc8470)
- [BoGo test suite](https://boringssl.googlesource.com/boringssl/+/master/ssl/test/)
- [rustls test infrastructure](https://github.com/rustls/rustls/tree/main/rustls-bogo-shim)
- [NIST CMVP](https://csrc.nist.gov/projects/cryptographic-module-validation-program)
