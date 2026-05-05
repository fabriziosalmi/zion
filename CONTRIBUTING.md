# Contributing to Zion Edge Gateway

We welcome contributions from the community to help improve Zion Edge Gateway.

## How to Contribute

We welcome many forms of contributions, including:
- Bug reports and feature requests
- Code contributions (bug fixes, performance optimizations, new features)
- Documentation improvements

### Reporting Bugs
If you find a bug, please create an issue containing:
1. Your Zion configuration file (`zion.toml`).
2. The operating system, architecture, and Rust version used.
3. Steps to reproduce the unexpected behavior.

### Feature Requests
Before spending time on a large PR, we strongly suggest opening a feature request issue to discuss your proposed changes with the maintainers. Since Zion focuses on minimizing allocations, architectural changes must be justified.

## Development Workflow

1. Fork the repository and create a branch from `master`.
2. Install the project git hooks once per clone:
   ```bash
   bash scripts/install-hooks.sh
   ```
   This sets `core.hooksPath` to `.githooks/`, which auto-injects the DCO
   `Signed-off-by` trailer, runs `cargo check` + `cargo test` on commit,
   and verifies version SSOT on push. See [Developer Certificate of Origin](#developer-certificate-of-origin-dco).
3. Build the project natively:
   ```bash
   cargo build
   ```
4. Run the test suite:
   ```bash
   cargo test
   ```
5. Ensure no warnings are reported:
   ```bash
   cargo clippy -- -D warnings
   cargo fmt --all -- --check
   ```
6. If your PR touches the request processing path (`src/dispatch.rs`, `src/waf.rs`, `src/proxy.rs`), please run the benchmarks:
   ```bash
   bash benchmarks/bench-matrix.sh
   ```

### Code Style Guidelines

- Avoid allocating memory (e.g., `String`, `Vec`) in request/response processing unless necessary. Use `std::borrow::Cow` or `bytes::BytesMut` instead.
- If `unsafe` is used, it must be accompanied by `// SAFETY:` explanatory comments.

## Developer Certificate of Origin (DCO)

All commits must be signed off per the [Developer Certificate of Origin](https://developercertificate.org/). This certifies that you wrote the contribution or otherwise have the right to submit it under the project's license.

If you ran `scripts/install-hooks.sh`, the `prepare-commit-msg` hook adds the trailer for you and `commit-msg` rejects any commit that ends up without one. Otherwise, sign manually:

```bash
git commit -s -m "Your commit message"
```

The trailer is a single line at the end of the commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

The CI workflow at `.github/workflows/dco.yml` rejects pull requests with any commit missing the sign-off. To fix existing commits in a branch:

```bash
git rebase --signoff <base-branch>
git push --force-with-lease
```

No CLA is required — DCO is sufficient. Project license is Apache 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Version SSOT (maintainers)

`Cargo.toml` is the single source of truth for the project version. Every other version reference (`Cargo.lock`, `deploy/helm/zion/Chart.yaml` `appVersion`, `vX.Y.Z` mentions in `README.md` and `docs/security/supply-chain.md`) must match it.

To cut a release:

```bash
scripts/bump-version.sh 0.1.11   # propagate the bump to every site
# add a CHANGELOG.md entry for 0.1.11
git commit -s -m "chore(release): v0.1.11"
git tag -s v0.1.11 -m "v0.1.11"
git push && git push --tags
```

The `pre-push` hook and `.github/workflows/version-sync.yml` will refuse any drift. To verify by hand:

```bash
scripts/check-version-sync.sh
```

## Pull Request Process

1. Provide a clear description explaining the changes.
2. Link related GitHub Issues.
3. Ensure every commit is signed off (DCO).
4. Wait for the CI pipeline to pass.
