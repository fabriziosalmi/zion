# FIPS 140-3 mode

Zion can be built against the FIPS-validated build of
[aws-lc-rs](https://github.com/aws/aws-lc-rs) by enabling the `fips`
Cargo feature:

```bash
cargo build --release --locked --features fips
```

This swaps the default `aws-lc-sys` backend for `aws-lc-fips-sys`, which
compiles the **AWS-LC FIPS module** from source and verifies its integrity
hash at link time (the FIPS Cryptographic Module Validation Program
requires that the validated binary's hash match the certificate exactly).

## What this gives you

- TLS handshake + record-layer cryptography (ECDHE, AES-GCM, SHA-2, HKDF)
  is performed by FIPS 140-3 validated code paths.
- The HMAC used by [the audit log](../guide/observability.md#audit-log)
  uses the same FIPS-validated HMAC-SHA-256.
- The session ticketer (`rustls::crypto::aws_lc_rs::Ticketer`) uses the
  validated AES-256-GCM primitive.

## What this does *not* give you

A FIPS *binary* is not a FIPS *deployment*. The certificate covers the
cryptographic module. Operating Zion in FIPS-compliant fashion still
requires:

1. **Cipher restrictions**. AWS-LC FIPS removes ChaCha20-Poly1305 from
   the allowed ciphersuites for TLS 1.2. TLS 1.3 ciphers
   (`TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`) remain available.
   Zion only negotiates TLS 1.3 by default — no operator action needed.
2. **Approved curves**. FIPS-approved ECDHE curves are P-256, P-384,
   P-521. X25519 (the default in many TLS 1.3 stacks) is not currently
   FIPS-approved. The `fips` feature pins the rustls cipher provider to
   the FIPS-approved subset; client connections that only offer X25519
   will fall back through normal negotiation.
3. **Random number generator**. AWS-LC FIPS uses the validated CTR-DRBG.
   The Linux kernel must supply the seed via `getrandom(2)` (which Zion
   indirectly does, through `Ticketer::new()` and elsewhere).
4. **Key handling**. The operator is responsible for storing private
   keys on FIPS-validated storage if the deployment requires it.
5. **Audit log retention**. The HMAC chain is FIPS-validated for
   integrity but the *retention* / WORM properties are operator-side.

## Validating a build

After building with `--features fips`, the resulting binary should:

```bash
# 1. Linkage check — the FIPS module is statically linked.
otool -L ./target/release/zion 2>/dev/null || ldd ./target/release/zion
# (No reference to the non-FIPS aws-lc-sys *.so)

# 2. Self-test — AWS-LC FIPS runs power-on self-tests at process start.
#    A failure aborts immediately. Successful start = self-tests passed.
ZION_CONFIG=zion.toml ./target/release/zion
# Look for the boot banner; absence of an FIPS self-test failure line
# is the green signal.

# 3. Cipher inventory — verify the offered cipher list against the
#    FIPS-approved subset. We ship a one-off helper script:
bash scripts/fips-self-check.sh ./target/release/zion
```

`scripts/fips-self-check.sh` is shipped under the `fips` feature only;
it boots Zion, performs a `s_client` handshake against `127.0.0.1:443`
with `-cipher` filtered to the approved subset, and asserts the
handshake succeeds.

## Cargo / CI integration

The `fips` feature is **not** part of `--all-features` because the
build pulls in `aws-lc-fips-sys`, which:

- requires CMake + clang on the build host,
- compiles the validated module from source on every CI run unless
  cached (the bindings rebuild is the slow step), and
- is incompatible with the `aws-lc-sys` (non-FIPS) build in the same
  resolver target — they pick different `aws-lc-sys` versions.

A separate CI job (`.github/workflows/ci.yml::clippy[flavor=fips]`)
exercises the build to keep it from rotting:

```yaml
- flavor: fips
  features: "--features fips"
```

The release pipeline does NOT publish a FIPS binary by default. To cut
a FIPS release artifact, dispatch `release.yml` with the `flavor: fips`
input — the matrix builds an additional asset suffixed `-fips` per
target.

## Compliance posture summary

| Aspect | Posture |
|---|---|
| Cryptographic module | AWS-LC FIPS 140-3 (Cert. #4759, in-process verification at link time) |
| Validated algorithms | TLS 1.3 AEAD suite, HMAC-SHA-256 (audit), AES-256-GCM (ticketer) |
| Approved curves enforced | P-256, P-384, P-521 (X25519 disabled by upstream provider) |
| Self-tests | Power-on, run by AWS-LC at process start |
| Key generation | CTR-DRBG seeded from `getrandom(2)` |
| Out of scope | Key storage, log retention, physical security |

## Related work

- [Track A](../security/supply-chain.md): SLSA L3 build provenance,
  cosign signatures — independent of FIPS but stacks with it.
- [Track B](../guide/observability.md): HMAC-chained audit log uses
  the same backend, so enabling `fips` automatically uplifts the
  audit-log integrity guarantee.
- [ADR-0007](../adr/0007-bicapa-msrv.md): MSRV story. The `fips` build
  inherits the "full feature" MSRV (currently 1.88).

## References

- [AWS-LC FIPS module](https://github.com/aws/aws-lc/tree/fips-2024-09-27)
- [aws-lc-rs FIPS guidance](https://github.com/aws/aws-lc-rs/blob/main/FIPS.md)
- [NIST CMVP 140-3](https://csrc.nist.gov/projects/cryptographic-module-validation-program)
- [rustls FIPS mode](https://docs.rs/rustls/latest/rustls/crypto/aws_lc_rs/index.html)
