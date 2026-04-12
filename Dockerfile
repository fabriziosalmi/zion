# ============================================================================
# Zion Edge Gateway — Production Dockerfile
#
# Multi-stage build: compile on Rust image, run on minimal Debian.
# Uses mimalloc as global allocator — no system malloc dependency.
#
# Build:
#   docker build -t zion:latest .
#
# Run:
#   docker run -d \
#     -v /path/to/zion.toml:/etc/zion/zion.toml:ro \
#     -v /path/to/certs:/etc/ssl/zion:ro \
#     -p 443:443 -p 80:80 \
#     --name zion zion:latest
# ============================================================================

# ── Stage 1: Build ──
FROM rust:1.86-bookworm AS builder
WORKDIR /build

# Cache dependency build (rebuild only when Cargo files change)
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && \
    cargo build --release 2>/dev/null || true && \
    rm -rf src

# Build the actual binary
COPY src/ src/
RUN cargo build --release && strip target/release/zion

# ── Stage 2: Runtime ──
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --no-create-home --shell /usr/sbin/nologin zion

COPY --from=builder /build/target/release/zion /usr/local/bin/zion
COPY zion.example.toml /etc/zion/zion.toml

# Create state directory for ACME
RUN mkdir -p /var/lib/zion && chown zion:zion /var/lib/zion

USER zion
EXPOSE 443 80

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD curl -sf http://localhost:80/healthz || exit 1

ENTRYPOINT ["zion"]
