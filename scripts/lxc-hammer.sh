#!/usr/bin/env bash
set -euo pipefail
# ============================================================================
# Zion — LXC integration hammer
#
# Run on the LXC at 192.168.100.59 (or any Linux box with kernel >= 5.10
# and root / CAP_NET_ADMIN + CAP_BPF). Drives every Track A/B/C piece
# end-to-end against a real kernel:
#
#   1. installs nightly + bpf-linker if missing
#   2. builds the eBPF object via xdp/build.sh
#   3. builds zion in release mode with all four feature flags enabled
#   4. runs the AIMP 2-node gossip smoke test (no privileges needed)
#   5. runs the XDP attach smoke test (needs CAP_NET_ADMIN)
#   6. runs the Track A A/B benchmark if `wrk` is available
#
# All steps are idempotent. A failure in one phase does not skip later
# phases — the script collects a pass/fail line per phase and exits
# non-zero if anything broke.
# ============================================================================

cd "$(dirname "$0")/.."
PROJECT_DIR="$PWD"

red()    { printf "\033[31m%s\033[0m\n" "$*"; }
green()  { printf "\033[32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }
banner() { printf "\n══════════════════════════════════════════════════════════════\n  %s\n══════════════════════════════════════════════════════════════\n" "$*"; }

# Phase results — `1` = pass, `0` = fail, blank = skipped.
declare -A PHASES=(
    [prereqs]=
    [ebpf_build]=
    [zion_build]=
    [aimp_smoke]=
    [xdp_smoke]=
    [bench]=
)

# ── Phase 1: prereqs ─────────────────────────────────────────────────
banner "Phase 1 — prereqs"
PASS=1
if [[ "$(uname -s)" != "Linux" ]]; then
    red "✗ not Linux ($(uname -s)); aborting"
    exit 2
fi
KVER="$(uname -r)"
echo "  kernel: $KVER"

# CPU ISA compatibility — zion's `.cargo/config.toml` defaults the
# x86_64-non-macos target to `target-cpu=x86-64-v3`, which requires
# AVX2/BMI2/FMA. Older Xeon/Core CPUs (Ivy Bridge and prior) only
# have v2 (SSE4.2/POPCNT). Without this fix, the *build scripts* of
# crates like aws-lc-sys SIGILL when cargo runs them.
#
# We can't use `CARGO_TARGET_..._RUSTFLAGS` here — cargo *concatenates*
# that env var with the file value (last `-C target-cpu=` wins, so v3
# would still win). The only reliable fix is to rewrite the file in
# place. Idempotent: the sed is a no-op if v3 is already absent.
if grep -qE '^flags\b.*\bavx2\b' /proc/cpuinfo; then
    echo "  ✓ CPU has AVX2 — leaving zion's x86-64-v3 default in place"
else
    yellow "  ! CPU lacks AVX2; downgrading .cargo/config.toml to x86-64-v2"
    sed -i 's/target-cpu=x86-64-v3/target-cpu=x86-64-v2/g' .cargo/config.toml
    echo "  ! purging cached build artifacts compiled under v3 flags…"
    cargo clean 2>/dev/null || true
fi

need() { command -v "$1" >/dev/null 2>&1; }
ensure() {
    local pkg="$1" check="$2" install="$3"
    if eval "$check" >/dev/null 2>&1; then
        echo "  ✓ $pkg"
    else
        yellow "  installing $pkg…"
        eval "$install" || PASS=0
    fi
}

if ! need cargo; then
    yellow "  installing rustup (this will take a minute)…"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --profile minimal \
        || PASS=0
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
fi
ensure "rust nightly-2026-01-15"  "rustup toolchain list | grep -q nightly-2026-01-15"  "rustup toolchain install nightly-2026-01-15 --profile minimal --component rust-src"
ensure "bpf-linker"               "command -v bpf-linker"                                 "cargo install bpf-linker --locked"
ensure "wrk"                      "command -v wrk"                                        "apt-get install -y --no-install-recommends wrk || true"
ensure "jq"                       "command -v jq"                                         "apt-get install -y --no-install-recommends jq || true"
PHASES[prereqs]=$PASS

# ── Phase 2: build eBPF object ───────────────────────────────────────
banner "Phase 2 — eBPF build"
if bash xdp/build.sh; then
    green "  ✓ eBPF object built"
    PHASES[ebpf_build]=1
    export ZION_XDP_OBJECT="$PROJECT_DIR/xdp/zion-xdp-prog/target/bpfel-unknown-none/release/zion-xdp-prog"
else
    red "  ✗ eBPF build failed"
    PHASES[ebpf_build]=0
fi

# ── Phase 3: zion build ──────────────────────────────────────────────
banner "Phase 3 — zion build (release, all features)"
if cargo build --release --no-default-features \
        --features "io-uring-accept,xdp,ml-waf,sovereign-aimp"; then
    green "  ✓ zion built"
    PHASES[zion_build]=1
else
    red "  ✗ zion build failed"
    PHASES[zion_build]=0
fi

# ── Phase 4: AIMP 2-node smoke ───────────────────────────────────────
banner "Phase 4 — AIMP 2-node gossip smoke"
if cargo run --release --no-default-features --features sovereign-aimp \
        --example aimp_smoke; then
    green "  ✓ AIMP gossip smoke passed"
    PHASES[aimp_smoke]=1
else
    red "  ✗ AIMP gossip smoke FAILED"
    PHASES[aimp_smoke]=0
fi

# ── Phase 5: XDP attach smoke ────────────────────────────────────────
banner "Phase 5 — XDP attach smoke"
if [[ $EUID -ne 0 ]]; then
    yellow "  ! not running as root; XDP attach requires CAP_NET_ADMIN"
    yellow "  ! skipping — re-run with sudo to exercise"
else
    IFACE="${ZION_XDP_IFACE:-lo}"
    if ZION_XDP_IFACE="$IFACE" cargo run --release --no-default-features \
            --features xdp --example xdp_smoke; then
        green "  ✓ XDP attach smoke passed (iface=$IFACE)"
        PHASES[xdp_smoke]=1
    else
        red "  ✗ XDP attach smoke FAILED"
        PHASES[xdp_smoke]=0
    fi
fi

# ── Phase 6: A/B benchmark ───────────────────────────────────────────
banner "Phase 6 — XDP+kTLS A/B benchmark"
if [[ -x benchmarks/bench-xdp-ktls.sh ]] && command -v wrk >/dev/null 2>&1; then
    # Port 80 is occupied on this LXC (docker-proxy → harbor). Generate
    # a bench-only config that listens on 81 / 8443 so the bench can
    # boot zion without colliding with the running container.
    BENCH_CFG="$(mktemp /tmp/zion-bench.XXXXXX.toml)"
    sed \
        -e 's|listen_http *= *"0\.0\.0\.0:80"|listen_http = "0.0.0.0:81"|' \
        -e 's|listen_https *= *"0\.0\.0\.0:443"|listen_https = "0.0.0.0:8443"|' \
        zion.example.toml > "$BENCH_CFG"
    echo "  using bench config: $BENCH_CFG (http=81, https=8443)"
    if SKIP_XDP_BUILD=1 ZION_CONFIG="$BENCH_CFG" bash benchmarks/bench-xdp-ktls.sh; then
        green "  ✓ benchmark complete"
        PHASES[bench]=1
    else
        red "  ✗ benchmark FAILED"
        PHASES[bench]=0
    fi
    rm -f "$BENCH_CFG"
else
    yellow "  ! wrk not installed or bench script missing — skipping"
fi

# ── Summary ──────────────────────────────────────────────────────────
banner "Summary"
EXIT=0
for phase in prereqs ebpf_build zion_build aimp_smoke xdp_smoke bench; do
    case "${PHASES[$phase]:-}" in
        1) green "  ✓ $phase" ;;
        0) red   "  ✗ $phase"; EXIT=1 ;;
        *) yellow "  - $phase (skipped)" ;;
    esac
done
exit $EXIT
