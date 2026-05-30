# syntax=docker/dockerfile:1.7
# ============================================================================
# Zion Edge Gateway — production container.
#
# Build  :  docker build -t zion:dev .
# Multi-arch (CI): handled by .github/workflows/release.yml via buildx.
#
# Hardening posture:
#   - `cargo build --locked`     — Cargo.lock must match committed state.
#   - SOURCE_DATE_EPOCH-aware     — reproducible builds when set by buildx/CI.
#   - OCI labels                  — image is self-describing for scanners.
#   - distroless runtime stage    — no shell, no apt, no SUID. Static-leaning.
#   - Non-root UID 65532          — matches gcr.io/distroless `nonroot`.
#   - HEALTHCHECK NONE            — distroless has no probe binary; probes
#                                   live in the orchestrator (Helm/Compose).
# ============================================================================

# ── Stage 1: Build ──
# Pinned to match rust-toolchain.toml. MSRV (Cargo.toml rust-version=1.82)
# only applies to the no-default-features build; this image bakes a full
# default-features binary so we need the same compiler we ship with.
FROM --platform=$BUILDPLATFORM rust:1.95-bookworm@sha256:adab7941580c74513aa3347f2d2a1f975498280743d29ec62978ba12e3540d3a AS builder

# Build arg flowed through by `docker buildx build --platform=...`.
# Lets us cross-compile on the native runner architecture.
ARG TARGETPLATFORM
ARG TARGETARCH
ARG TARGETVARIANT
# CI passes the commit timestamp; falls back to a fixed deterministic value
# locally so a `docker build` on a clean tree is still bitwise stable.
ARG SOURCE_DATE_EPOCH=0
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

WORKDIR /build

# Native build deps for aws-lc-rs / mimalloc (CMake + clang).
# musl-tools/cross-toolchains are intentionally NOT installed here — the
# CI release pipeline cross-compiles via cargo-zigbuild on the host runner;
# this Dockerfile compiles natively on the target arch under buildx.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        cmake pkg-config build-essential clang ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Pre-warm the dependency closure with a stub `main`. The Cargo cache for
# /usr/local/cargo/registry survives the next COPY thanks to BuildKit's
# layer cache, so application changes don't rebuild every dep.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
RUN mkdir -p src benches && \
    echo 'fn main() {}' > src/main.rs && \
    # The manifest declares `[[bench]]` targets (Criterion, harness=false);
    # Cargo refuses to even parse it if their source files are absent. Create
    # empty placeholders for whatever benches Cargo.toml lists (read from the
    # manifest so the set never drifts) — `cargo build --release` doesn't
    # compile benches, so empty files are enough. The real sources are copied
    # for the application build below.
    awk '/^\[\[bench\]\]/{b=1} b&&/^name[[:space:]]*=/{gsub(/[" ]/,"",$3); print $3; b=0}' Cargo.toml \
      | while IFS= read -r bench; do : > "benches/${bench}.rs"; done && \
    cargo build --release --locked && \
    rm -rf src benches target/release/zion target/release/zion.d \
           target/release/deps/zion-* target/release/build/zion-*

# Real source. `benches/` is copied too: the manifest declares `[[bench]]`
# targets, and Cargo won't parse it if their files are absent (the binary
# build below doesn't compile benches, so this only satisfies the parse).
COPY src/ src/
COPY benches/ benches/
COPY .cargo/ .cargo/
RUN cargo build --release --locked && \
    strip target/release/zion && \
    # Best-effort canonicalization for reproducibility.
    touch -d "@${SOURCE_DATE_EPOCH}" target/release/zion

# Pre-create the ACME state directory with the nonroot UID we use at runtime.
# Distroless has no shell to mkdir at runtime, and `COPY --chown` is the only
# way to lay down a directory with the right ownership in a scratch-style FS.
RUN mkdir -p /out/var/lib/zion && \
    chown -R 65532:65532 /out/var/lib/zion && \
    chmod 700 /out/var/lib/zion

# ── Stage 2: Runtime — distroless, non-root, no shell. ──
# `cc-debian12` provides libc + ca-certificates + tzdata. We drop into
# `nonroot` (UID 65532). For a fully static binary use a separate target
# (linux-musl) and ship via gcr.io/distroless/static — that path is taken
# by the CI release workflow when building from the precompiled musl artifact.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:bd2899c12b335c827750ccf2359879eab09c09b206023dcebea408947d54127c AS runtime

# Re-declare so labels can interpolate it.
ARG SOURCE_DATE_EPOCH=0

# OCI labels — surfaced by GHCR/Quay UIs and by image scanners.
LABEL org.opencontainers.image.title="Zion Edge Gateway" \
      org.opencontainers.image.description="High-performance Rust TLS reverse proxy with WAF" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/fabriziosalmi/zion" \
      org.opencontainers.image.url="https://github.com/fabriziosalmi/zion" \
      org.opencontainers.image.documentation="https://fabriziosalmi.github.io/zion" \
      org.opencontainers.image.vendor="Fabrizio Salmi" \
      org.opencontainers.image.created="$SOURCE_DATE_EPOCH"

COPY --from=builder /build/target/release/zion /usr/local/bin/zion
COPY zion.example.toml /etc/zion/zion.toml
# /var/lib/zion holds ACME state (`--features acme`). Pre-created in the
# builder with ownership 65532:65532; copied verbatim into the runtime FS.
COPY --from=builder /out/var/lib/zion /var/lib/zion

USER 65532:65532
EXPOSE 443 80

# Distroless ships no curl/wget/nc. The daemon's `/healthz` (src/health.rs,
# ~1us inline fast-path) is meant to be probed *externally* — by Kubernetes
# liveness/readiness, by a sidecar, or by a docker-compose service that has
# a shell. Baking an HTTP probe into the image would require pulling curl
# back in, which is exactly what distroless is designed to avoid.
#
# The Helm chart (deploy/helm) configures HTTP probes on /healthz and /readyz.
HEALTHCHECK NONE

ENTRYPOINT ["/usr/local/bin/zion"]
