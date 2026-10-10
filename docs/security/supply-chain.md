# Supply chain security

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
gh release download v0.12.0 -R fabriziosalmi/zion \
    -p 'zion-v0.12.0-x86_64-unknown-linux-musl.tar.gz' \
    -p 'SHA256SUMS' \
    -p 'zion-sbom.cdx.json'

# 2. Verify the checksum.
sha256sum --check --ignore-missing SHA256SUMS

# 3. Verify the SLSA build provenance bound to the artifact's hash.
gh attestation verify zion-v0.12.0-x86_64-unknown-linux-musl.tar.gz \
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
IMAGE=ghcr.io/fabriziosalmi/zion:v0.12.0

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

The release workflow builds every Linux target with `cargo zigbuild`, on Rust
**1.88.0** (set by the workflow; `rust-toolchain.toml` is the development pin and
is not used for releases), with **`--features dist`** (acme + init + auth), the
commit stamped into the version string (`ZION_GIT_SHA`, `ZION_COMMIT_DATE`),
`SOURCE_DATE_EPOCH` set to the commit time, then `strip` and a deterministic
`tar` (owner 0, `--mtime=@$SOURCE_DATE_EPOCH`, `--sort=name`).

A binary also carries the source paths of its dependencies (the locations of
their panics), and those are the build machine's. From the release after 0.12 on,
the workflow remaps them to fixed names
([`scripts/remap-rustflags.sh`](https://github.com/fabriziosalmi/zion/blob/master/scripts/remap-rustflags.sh)):
cargo's home becomes `/cargo`, and the standard library's sources, which a toolchain
with the `rust-src` component reads from its own directory, become the compiler's
`/rustc/<commit>`. It also builds with an empty zig cache: zig keeps compiled C
objects by path and flags, not by `SOURCE_DATE_EPOCH`, and the allocator's C code
contains the date and time of its compilation, so an object left by another day's
build of the same source would be reused with that day in it. With those, the bytes
do not depend on the directory, on where cargo's home is, or on the toolchain's
components. To rebuild the Linux musl artifact:

```bash
git clone --depth 1 --branch v0.12.0 https://github.com/fabriziosalmi/zion && cd zion
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
export ZION_GIT_SHA=$(git rev-parse --short=12 HEAD)
export ZION_COMMIT_DATE=$(git show -s --format=%cd --date=format:%Y-%m-%d HEAD)
# needs zig 0.13.0 and cargo-zigbuild 0.23.4 on PATH
#   (cargo install --locked cargo-zigbuild --version 0.23.4)
rustup toolchain install 1.88.0 --target x86_64-unknown-linux-musl
export ZIG_GLOBAL_CACHE_DIR=$(mktemp -d)
if [ -f scripts/remap-rustflags.sh ]; then   # the releases after 0.12
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="$(bash scripts/remap-rustflags.sh +1.88.0)"
fi
cargo +1.88.0 zigbuild --release --locked --features dist --target x86_64-unknown-linux-musl
strip target/x86_64-unknown-linux-musl/release/zion
sha256sum target/x86_64-unknown-linux-musl/release/zion
```

`SHA256SUMS` lists the **archives**, not the binaries. Compare the binary with
the one inside the published archive:

```bash
tar -xzOf zion-v0.12.0-x86_64-unknown-linux-musl.tar.gz zion | sha256sum
```

or recreate the archive with the same `tar` flags and compare it against
`SHA256SUMS`. The toolchain is pinned end to end: Rust 1.88.0, `zig` 0.13.0 and
`cargo-zigbuild` 0.23.4 (the versions that built v0.12.0; the workflow installs
exactly these).

**Releases up to 0.12** were built without the remapping, and have no such script.
Their bytes contain the paths of the runner that built them, so a rebuild has to
match two things about that machine as well:

* cargo's home at `/home/runner/.cargo`
  (`sudo mkdir -p /home/runner && sudo chown "$(id -u):$(id -g)" /home/runner`, then
  `CARGO_HOME=/home/runner/.cargo` on the `cargo` command);
* a toolchain **without** the `rust-src` component, which this repository's
  `rust-toolchain.toml` adds to any toolchain used in a checkout: install one for the
  purpose (`export RUSTUP_HOME=$(mktemp -d)` before the `rustup toolchain install`,
  with `--profile minimal`).

Checked on 2026-10-10 on a machine that is not a GitHub runner. The 0.12 release
rebuilt with those two conditions is the published binary byte for byte; with cargo's
home elsewhere, or with a toolchain that has `rust-src`, it is not. With the remapping
flags, two builds of that source that differed in the directory, in cargo's home and in
the toolchain's components were identical to each other; and one of them made again on
a zig cache that had served another day's build was not, by the date and the time in
the allocator's object.

A scheduled job, [`reproducibility.yml`](https://github.com/fabriziosalmi/zion/blob/master/.github/workflows/reproducibility.yml),
does this every Monday for the latest release: it rebuilds the Linux musl binary
from the tag and compares it with the published one, failing (and keeping both
binaries) on a difference. A release built with the remapping is rebuilt somewhere
else on purpose (another cargo home, a toolchain with `rust-src`), so that the job
checks what the recipe promises; an older one is rebuilt where the runner happens
to match the release's. On pull requests that touch the build, the same workflow
builds the tree in two such places and requires one binary, and a third time without
the flags, which must differ. It covers `x86_64-unknown-linux-musl` only; the other
targets are built by the same workflow but are not rebuilt and compared.
A difference you can explain is worth an issue (with your toolchain versions).
Provenance does not depend on any of this: every artifact carries a SLSA build
attestation (`gh attestation verify`) and the commit in its version string.

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

### Keep the CI cargo-vet version in lockstep with the lock

`imports.lock` (and the rest of the baseline) is written by whatever
`cargo-vet` you run locally, and its on-disk schema evolves between
releases. CI must run a `cargo-vet` that can read what your local one
wrote — a newer CI tool reads an older lock fine, but an **older** CI
tool rejects a newer lock with a hard parse error, e.g.:

```text
ERROR × Failed to parse toml file
  ╰─▶ missing field `user-id` for key `publisher.<crate>` at imports.lock:NNNN
```

That is not a real audit failure — it's a version skew. Two rules keep
it from happening:

1. CI builds `cargo-vet` from crates.io at a **pinned** version
   (`cargo install --locked cargo-vet@X.Y.Z` in the `vet` job), not a
   prebuilt binary. There is no prebuilt for releases past `0.10.0`
   (mozilla/cargo-vet cut no GitHub release for `0.10.1`+), so
   `install-action`/`cargo-binstall` can only ever fetch `0.10.0` — too
   old for a lock written by a current local tool.
2. When you bump your local `cargo-vet` and regenerate the baseline,
   bump the pin in `supply-chain.yml`'s `vet` job to the same version in
   the same PR. `cargo vet --version` locally tells you the number to use.

The job runs on a GitHub-hosted runner (not the self-hosted pool), whose
network reliably fetches the crates.io source — the self-hosted runners
were observed corrupting the download (sha256 mismatch).

## Reporting a supply-chain issue

If a published artifact fails any of the verification steps above, treat it
as a security incident and report it via
[GitHub Security Advisories](https://github.com/fabriziosalmi/zion/security/advisories/new).
We will revoke the affected tag, publish a replacement, and document the
incident in [SECURITY.md](../../SECURITY.md).
