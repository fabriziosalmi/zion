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
2. Build the project natively:
   ```bash
   cargo build
   ```
3. Run the test suite:
   ```bash
   cargo test
   ```
4. Ensure no warnings are reported:
   ```bash
   cargo clippy -- -D warnings
   cargo fmt --all -- --check
   ```
5. If your PR touches the request processing path (`src/dispatch.rs`, `src/waf.rs`, `src/proxy.rs`), please run the benchmarks:
   ```bash
   bash benchmarks/bench-matrix.sh
   ```

### Code Style Guidelines

- Avoid allocating memory (e.g., `String`, `Vec`) in request/response processing unless necessary. Use `std::borrow::Cow` or `bytes::BytesMut` instead.
- If `unsafe` is used, it must be accompanied by `// SAFETY:` explanatory comments.

## Pull Request Process

1. Provide a clear description explaining the changes.
2. Link related GitHub Issues.
3. Wait for the CI pipeline to pass.
