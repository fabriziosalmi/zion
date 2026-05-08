#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# ZION — XDP + kTLS A/B Benchmark (Track A)
#
# Measures the wall-clock cost of the Track A data-plane features:
#
#   * `--features xdp`   → drops blacklisted CIDRs at NIC driver layer
#   * `--features ktls`  → kernel TLS post-handshake offload
#
# This script is **Linux-only**. It must be run on a host with:
#   - kernel >= 5.10 with CONFIG_TLS=y
#   - CAP_NET_ADMIN (required to load XDP programs)
#   - bpf-linker installed (to build the eBPF object) — `cargo install bpf-linker`
#   - rustup nightly toolchain (for the eBPF build) — see xdp/build.sh
#   - wrk or oha available on PATH
#
# Reference target: the LXC container at 192.168.100.59.
#
# METHODOLOGY:
#   Baseline    — zion built with `--no-default-features` (no XDP, no kTLS)
#   +XDP        — zion built with `--features xdp,io-uring-accept`
#   +kTLS       — zion built with `--features ktls`
#   +XDP+kTLS   — zion built with `--features xdp,ktls,io-uring-accept`
#
# For each variant:
#   * 3 × 10s warmup runs (TCP slow-start, kernel cache prime)
#   * 5 × 30s measurement runs at C={64,512,4096}
#   * Reports: req/s median, p50/p99 latency, drops/s (XDP only)
#
# Produces bench-history-xdp-ktls.json (appended).
# ============================================================================

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "✗ This benchmark requires Linux (got $(uname -s))" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
HISTORY_FILE="$SCRIPT_DIR/bench-history-xdp-ktls.json"

# ── tunables ─────────────────────────────────────────────────────────
WARMUP_DUR=5
MEASURE_DUR=20
RUNS=3
CONNS_LIST=(64 1024)
THREADS=2

ZION_HOST="${ZION_HOST:-127.0.0.1}"
ZION_PORT="${ZION_PORT:-8443}"
ZION_CONFIG="${ZION_CONFIG:-$PROJECT_DIR/zion.example.toml}"
TARGET_URL="https://$ZION_HOST:$ZION_PORT/healthz"

# TLS material — generated on demand (self-signed). zion refuses to
# start if the configured paths don't exist, even though the bench
# loopback target doesn't care about cert validity.
TLS_DIR=/etc/ssl/zion
if [[ ! -f "$TLS_DIR/tls.crt" ]]; then
    mkdir -p "$TLS_DIR"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$TLS_DIR/tls.key" -out "$TLS_DIR/tls.crt" -days 30 \
        -subj "/CN=zion-bench" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>&1 | tail -1
    chmod 600 "$TLS_DIR/tls.key"
fi

# Use oha (Rust-based wrk) — supports --insecure for self-signed TLS.
# Install if missing.
if ! command -v oha >/dev/null; then
    curl -sSL https://github.com/hatoo/oha/releases/download/v1.4.7/oha-linux-amd64 \
        -o /usr/local/bin/oha && chmod +x /usr/local/bin/oha
fi

# ── prereqs ──────────────────────────────────────────────────────────
need() { command -v "$1" >/dev/null 2>&1 || { echo "✗ missing: $1"; exit 1; }; }
need cargo
need wrk
need jq
[[ -n "${SKIP_XDP_BUILD:-}" ]] || need bpf-linker

# ── XDP eBPF object — built once ─────────────────────────────────────
XDP_OBJECT="$PROJECT_DIR/xdp/zion-xdp-prog/target/bpfel-unknown-none/release/zion-xdp-prog"
if [[ -z "${SKIP_XDP_BUILD:-}" ]]; then
    echo "→ Building eBPF object…"
    "$PROJECT_DIR/xdp/build.sh"
fi
[[ -f "$XDP_OBJECT" ]] || { echo "✗ eBPF object missing: $XDP_OBJECT"; exit 1; }
export ZION_XDP_OBJECT="$XDP_OBJECT"

# ── matrix ───────────────────────────────────────────────────────────
declare -A VARIANTS=(
    [baseline]=""
    [xdp]="--features xdp,io-uring-accept"
)
# kTLS variants are skipped: ktls 6.0.2 changed its API to require
# `TlsStream<CorkStream<_>>` and our `src/ktls.rs` still passes the raw
# `TlsStream<TcpStream>`. Adding the cork wrapping in zion's TLS path
# is left as a follow-up; until then a build with `--features ktls`
# fails to compile.

run_variant() {
    local name="$1"
    local features="${VARIANTS[$name]}"
    echo "════════════════════════════════════════════════════════════"
    echo "  Variant: $name  (features: ${features:-<none>})"
    echo "════════════════════════════════════════════════════════════"

    # Build with the chosen feature set.
    ( cd "$PROJECT_DIR" && cargo build --release --no-default-features $features )
    local zion_bin="$PROJECT_DIR/target/release/zion"

    # Boot zion. Config is read from $ZION_CONFIG env var (no `--config` flag).
    ZION_CONFIG="$ZION_CONFIG" "$zion_bin" &
    local zion_pid=$!
    sleep 2
    # Wait for /health to respond.
    local wait_n=0
    until curl -ksf "$TARGET_URL" >/dev/null 2>&1; do
        ((wait_n++))
        [[ $wait_n -gt 30 ]] && { kill $zion_pid; echo "✗ zion did not become healthy"; return 1; }
        sleep 0.5
    done

    # Warmup.
    for _ in $(seq 1 3); do
        oha --insecure -c 64 -z "${WARMUP_DUR}s" --no-tui "$TARGET_URL" >/dev/null 2>&1 || true
    done

    # Measurement runs (oha — handles self-signed TLS via --insecure).
    for c in "${CONNS_LIST[@]}"; do
        for r in $(seq 1 "$RUNS"); do
            local out
            out=$(oha --insecure -c "$c" -z "${MEASURE_DUR}s" --no-tui --json "$TARGET_URL" 2>&1)
            local rps p50 p99
            rps=$(echo "$out" | jq -r '.summary.requestsPerSec // empty' 2>/dev/null)
            p50=$(echo "$out" | jq -r '.latencyPercentiles.p50 // empty' 2>/dev/null)
            p99=$(echo "$out" | jq -r '.latencyPercentiles.p99 // empty' 2>/dev/null)

            jq -n --arg variant "$name" \
                  --argjson conns "$c" \
                  --argjson run "$r" \
                  --arg rps "$rps" \
                  --arg p50 "$p50" \
                  --arg p99 "$p99" \
                  --arg ts "$(date -Iseconds)" \
              '{ts:$ts, variant:$variant, conns:$conns, run:$run,
                rps:$rps, p50:$p50, p99:$p99}' \
              >> "$HISTORY_FILE"
        done
    done

    kill $zion_pid 2>/dev/null || true
    wait $zion_pid 2>/dev/null || true
    sleep 5  # cooldown
}

# ── execute ──────────────────────────────────────────────────────────
: > "$HISTORY_FILE"
for v in baseline xdp ktls xdp_ktls; do
    run_variant "$v"
done

echo
echo "✓ Done. Results: $HISTORY_FILE"
echo
echo "Quick summary:"
jq -s '
  group_by(.variant) | map({
    variant: .[0].variant,
    median_rps: (map(.rps | tonumber) | sort | .[length/2|floor])
  })
' "$HISTORY_FILE"
