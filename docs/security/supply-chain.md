# Supply Chain Security

Every Zion release ships with cryptographic evidence — provenance, SBOM, and
signatures — that lets a consumer verify *what* they're running and *where it
came from* without trusting the registry, GitHub, or the maintainer's keys.

This page is the authoritative checklist for verifying a Zion artifact.

## Trust posture, in one paragraph

Zion releases are built by a public GitHub Actions workflow
([release.yml](https://github.com/fabriziosalmi/zion/blob/master/.github/workflows/release.yml))
on GitHub-hosted runners. Every binary, every container image, and the
release-level `SHA256SUMS` carry a SLSA v1.0 build provenance attestation
([attest-build-provenance](https://github.com/actions/attest-build-provenance))
signed by the workflow's OIDC identity through Sigstore. Container images
are additionally signed keyless with [cosign](https://github.com/sigstore/cosign)
and carry a CycloneDX SBOM attestation. There are no long-lived signing keys
to leak; every signature is anchored in the public Rekor transparency log.

## What you get with each release

| Artifact | Format | Where |
|----------|--------|-------|
| Binaries (7 targets, see below) | `tar.gz` / `zip` | GitHub Releases page |
| `SHA256SUMS` | sha256sum text | GitHub Releases page |
| `zion-sbom.cdx.json` | CycloneDX 1.5 JSON | GitHub Releases page |
| Build provenance (in-toto v1.0) | Sigstore bundle | `gh attestation` / Rekor |
| Container image | OCI multi-arch (amd64, arm64) | `ghcr.io/fabriziosalmi/zion` |
| Image signature | cosign keyless | embedded in registry |
| Image SBOM attestation | CycloneDX-in-DSSE | embedded in registry |

Targets shipped:

- `x86_64-unknown-linux-gnu`
- `x86_64-unknown-linux-musl` (fully static)
- `aarch64-unknown-linux-gnu`
- `aarch64-unknown-linux-musl` (fully static)
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-pc-windows-msvc`

## Verifying a binary release

You need the GitHub CLI (`gh >= 2.49`) and `cosign >= 2.2`.

```bash
# 1. Download the artifact + SHA256SUMS from the release page.
gh release download v0.4.4 -R fabriziosalmi/zion \
    -p 'zion-v0.4.4-x86_64-unknown-linux-musl.tar.gz' \
    -p 'SHA256SUMS' \
    -p 'zion-sbom.cdx.json'

# 2. Verify the checksum.
sha256sum --check --ignore-missing SHA256SUMS

# 3. Verify the SLSA build provenance bound to the artifact's hash.
gh attestation verify zion-v0.4.4-x86_64-unknown-linux-musl.tar.gz \
    --owner fabriziosalmi

# Step 3 fails if:
#   - the artifact wasn't built by the public release.yml workflow, OR
#   - the workflow ran from a fork, OR
#   - the Rekor log entry has been tampered with.
```

For the SBOM:

```bash
# Same provenance check, applied to the SBOM file itself.
gh attestation verify zion-sbom.cdx.json --owner fabriziosalmi

# Inspect the dep graph if you want to scan for CVEs locally.
syft scan zion-sbom.cdx.json -o table
grype zion-sbom.cdx.json
```

## Verifying a container image

```bash
IMAGE=ghcr.io/fabriziosalmi/zion:v0.4.4

# 1. Pin to the digest immediately — tags are mutable, digests are not.
DIGEST=$(crane digest "$IMAGE")
echo "Pinned: ${IMAGE}@${DIGEST}"

# 2. Verify the cosign keyless signature.
#    The certificate-identity-regexp asserts that the signature was produced
#    by the canonical release workflow on the canonical repository — *not*
#    a fork, not a manual run from a developer laptop.
cosign verify "${IMAGE}@${DIGEST}" \
    --certificate-identity-regexp "^https://github.com/fabriziosalmi/zion/\\.github/workflows/release\\.yml@refs/tags/v" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    | jq .

# 3. Verify the SLSA build provenance attestation.
cosign verify-attestation "${IMAGE}@${DIGEST}" \
    --type slsaprovenance \
    --certificate-identity-regexp "^https://github.com/fabriziosalmi/zion/\\.github/workflows/release\\.yml@refs/tags/v" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

# 4. Verify the SBOM attestation and extract it.
cosign verify-attestation "${IMAGE}@${DIGEST}" \
    --type cyclonedx \
    --certificate-identity-regexp "^https://github.com/fabriziosalmi/zion/\\.github/workflows/release\\.yml@refs/tags/v" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  | jq -r '.payload' | base64 -d | jq '.predicate' > image-sbom.json
```

If you operate Kubernetes and want admission-time enforcement, the
`certificate-identity-regexp` above is the value to plug into a
[sigstore-policy-controller](https://github.com/sigstore/policy-controller)
or [Kyverno](https://kyverno.io/policies/?policytypes=cosign) `ClusterImagePolicy`.

## Reproducing a build

Builds are bit-stable to the extent the toolchain allows: the workflow exports
`SOURCE_DATE_EPOCH` from the commit timestamp, sorts archive entries
deterministically, and pins the Rust toolchain via
[`rust-toolchain.toml`](../../rust-toolchain.toml). To reproduce locally:

```bash
git checkout v0.4.4
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
# Linux musl example — matches the release artifact byte-for-byte
# (modulo strip's stable behavior on your distro).
cargo install --locked cargo-zigbuild
rustup target add x86_64-unknown-linux-musl
cargo zigbuild --release --locked --target x86_64-unknown-linux-musl
strip target/x86_64-unknown-linux-musl/release/zion
sha256sum target/x86_64-unknown-linux-musl/release/zion
```

Compare the resulting hash to the release `SHA256SUMS`. Any drift is a
reproducibility defect — file an issue with your toolchain version and we'll
chase it.

## Policy: what the supply-chain pipeline blocks

[supply-chain.yml](https://github.com/fabriziosalmi/zion/blob/master/.github/workflows/supply-chain.yml)
runs on every PR, daily at 06:00 UTC, and on every release tag. It blocks
merge / release if:

- `cargo audit` finds an unfixed advisory, an unmaintained crate, or a yanked version
- `cargo deny check advisories` flags any `RUSTSEC-*` not present in the explicit ignore list ([deny.toml](../../deny.toml))
- `cargo deny check licenses` finds a license outside the SPDX allowlist
- `cargo deny check bans` resolves a denylisted or wildcard-versioned crate
- `cargo deny check sources` resolves a crate from anywhere except `crates.io`
- `cargo vet --locked` finds a transitive crate without an audit verdict in `supply-chain/audits.toml`, an imported feed, OR an explicit `[[exemptions.X]]` row in `supply-chain/config.toml`
- CodeQL ([codeql.yml](https://github.com/fabriziosalmi/zion/blob/master/.github/workflows/codeql.yml)) raises a critical finding on Rust or Actions code

Informational signals (do not block, but produce artifacts you can review):

- `cargo geiger` — quantifies the unsafe surface across the dep graph
- `OSSF Scorecard` — overall repo posture grade, published to the Security tab

## Updating the cargo-vet baseline

`supply-chain/` is the cargo-vet baseline. It contains:

- `config.toml` — imported audit feeds (mozilla, google, embark,
  bytecode-alliance, isrg, zcash) plus `[[exemptions.X]]` rows
  for crates not yet covered by an audit. Exemptions are explicit:
  the auditor can read the file and see exactly which crates the
  project has chosen to accept without an upstream verdict.
- `audits.toml` — Zion-local audits (`cargo vet certify <crate>`).
  Empty at v0 baseline; populate as crates get reviewed.
- `imports.lock` — the resolver's cache of the imported feeds.
  Refreshed on every `cargo vet` run that omits `--locked`.

When dependencies change (Cargo.lock update, new crate added, etc.):

```bash
# Refresh the imports cache and let cargo-vet apply the new
# transitive set against the baseline.
cargo vet

# If a new crate has no audit and no exemption, the run fails with
# a "missing audit" diagnostic. Two paths to resolve:
#
#   (a) An imported feed audits the crate but the baseline doesn't
#       know yet — `cargo vet` will write the import to imports.lock.
#       Just commit the updated supply-chain/imports.lock.
#
#   (b) Genuinely new crate that's not in any feed — review the
#       crate yourself and certify:
cargo vet certify <crate-name> <version>
#       This walks the file diff, lets you mark `safe-to-deploy` /
#       `safe-to-run`, and writes the audit to supply-chain/audits.toml.
#
#   (c) Pragmatic exemption (you've reviewed informally and want to
#       defer the formal certify) — add to supply-chain/config.toml:
#         [[exemptions.<crate-name>]]
#         version = "X.Y.Z"
#         criteria = "safe-to-deploy"

# Periodically prune redundant exemptions: a crate that started as
# an exemption is now covered by an imported feed.
cargo vet prune

# Final check before commit — must pass under --locked.
cargo vet --locked
```

The CI job (`cargo-vet` in `supply-chain.yml`) runs `cargo vet --locked`
on every PR. A red `cargo-vet` check means a transitive change
introduced a crate that fails this gate; the PR author resolves via
one of the three paths above.

## Reporting a supply-chain issue

If a published artifact fails any of the verification steps above, treat it
as a security incident and report it via
[GitHub Security Advisories](https://github.com/fabriziosalmi/zion/security/advisories/new).
We will revoke the affected tag, publish a replacement, and document the
incident in [SECURITY.md](../../SECURITY.md).
