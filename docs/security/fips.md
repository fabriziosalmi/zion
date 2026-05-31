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
#    FIPS-approved subset with a direct TLS 1.3 handshake:
echo | openssl s_client -connect 127.0.0.1:443 -tls1_3 \
    -ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256 2>/dev/null \
    | grep -E 'Protocol|Cipher'
# A successful handshake on an approved AEAD suite is the green signal.
```

> **Honest note:** there is currently **no** bundled `fips-self-check.sh`
> helper. The `openssl s_client` cipher-inventory check above is the
> documented manual procedure; a packaged self-check script is tracked as
> future work, not something this repo ships today.

## Cargo / CI integration

The `fips` feature is **not** part of `--all-features` because the
build pulls in `aws-lc-fips-sys`, which:

- requires CMake + clang on the build host,
- compiles the validated module from source on every CI run unless
  cached (the bindings rebuild is the slow step), and
- is incompatible with the `aws-lc-sys` (non-FIPS) build in the same
  resolver target — they pick different `aws-lc-sys` versions.

> **Current status (honest posture):** the FIPS build is **not yet wired
> into CI or the release pipeline.** There is no `flavor: fips` job in
> `ci.yml`, and `release.yml` publishes no `-fips` artifact. A FIPS build
> is therefore a **manual** `cargo build --release --features fips` today,
> and it does **not** carry the SLSA provenance attestation that the
> default release binaries do (see [supply-chain](supply-chain.md)).
>
> This matters for the FIPS *chain of custody*: a self-built FIPS binary
> is **unattested** — you are the build authority and the custody chain is
> yours to establish (reproducible toolchain, recorded build environment,
> signed artifact). The validated cryptographic *module* is still
> AWS-LC's; what an in-house build does not give you is third-party
> evidence of *how your specific binary* was produced.
>
> Wiring a `fips` clippy flavor into CI (to keep the build from rotting)
> and an attested `-fips` release asset are tracked as future work.

## Compliance posture summary

| Aspect | Posture |
|---|---|
| Cryptographic module | AWS-LC FIPS 140-3 (Cert. #4759, in-process verification at link time) |
| Validated algorithms | TLS 1.3 AEAD suite, HMAC-SHA-256 (audit), AES-256-GCM (ticketer) |
| Approved curves enforced | P-256, P-384, P-521 (X25519 disabled by upstream provider) |
| Self-tests | Power-on, run by AWS-LC at process start |
| Key generation | CTR-DRBG seeded from `getrandom(2)` |
| Build attestation | **None for FIPS builds today** — manual build, no CI/release wiring; SLSA provenance covers the default binaries only |
| Out of scope | Key storage, log retention, physical security |

## Related work

- [Track A](../security/supply-chain.md): SLSA L3 build provenance,
  cosign signatures — covers the **default** release binaries; it would
  stack with FIPS once a `-fips` release artifact is published (not today).
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
