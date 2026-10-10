#!/usr/bin/env bash
set -euo pipefail
# ============================================================================
# Zion — LXC integration hammer
#
# Run on any Linux box (kernel >= 5.10). Builds zion with the experimental /
# mesh feature set and drives the AIMP gossip smoke test against a real kernel:
#
#   1. installs a stable rust toolchain if missing
#   2. builds zion in release mode with the mesh + ml-waf features
#   3. runs the AIMP 2-node gossip smoke test (no privileges needed)
#
# The in-kernel deep-tech tracks (XDP pre-filter, eBPF SO_REUSEPORT demux) are
# frozen — see issues #51/#52/#53 — so this hammer no longer builds an eBPF
# object or attaches an XDP program.
#
# All steps are idempotent. A failure in one phase does not skip later phases —
# the script collects a pass/fail line per phase and exits non-zero if anything
# broke.
# ============================================================================

cd "$(dirname "$0")/.."

red()    { printf "\033[31m%s\033[0m\n" "$*"; }
green()  { printf "\033[32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }
banner() { printf "\n══════════════════════════════════════════════════════════════\n  %s\n══════════════════════════════════════════════════════════════\n" "$*"; }

# Phase results — `1` = pass, `0` = fail, blank = skipped.
declare -A PHASES=(
    [prereqs]=""
    [zion_build]=""
    [aimp_smoke]=""
)

# ── Phase 1: prereqs ─────────────────────────────────────────────────
banner "Phase 1 — prereqs"
PASS=1
if [[ "$(uname -s)" != "Linux" ]]; then
    red "✗ not Linux ($(uname -s)); aborting"
    exit 2
fi
echo "  kernel: $(uname -r)"

need() { command -v "$1" >/dev/null 2>&1; }
if ! need cargo; then
    yellow "  installing rustup (this will take a minute)…"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --profile minimal \
        || PASS=0
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
else
    echo "  ✓ cargo"
fi
PHASES[prereqs]=$PASS

# ── Phase 2: zion build ──────────────────────────────────────────────
banner "Phase 2 — zion build (release, mesh + ml-waf features)"
if cargo build --release --no-default-features \
        --features "io-uring-accept,ml-waf,sovereign-aimp"; then
    green "  ✓ zion built"
    PHASES[zion_build]=1
else
    red "  ✗ zion build failed"
    PHASES[zion_build]=0
fi

# ── Phase 3: AIMP 2-node smoke ───────────────────────────────────────
banner "Phase 3 — AIMP 2-node gossip smoke"
if cargo run --release --no-default-features --features sovereign-aimp \
        --example aimp_smoke; then
    green "  ✓ AIMP gossip smoke passed"
    PHASES[aimp_smoke]=1
else
    red "  ✗ AIMP gossip smoke FAILED"
    PHASES[aimp_smoke]=0
fi

# ── Summary ──────────────────────────────────────────────────────────
banner "Summary"
EXIT=0
for phase in prereqs zion_build aimp_smoke; do
    case "${PHASES[$phase]:-}" in
        1) green "  ✓ $phase" ;;
        0) red   "  ✗ $phase"; EXIT=1 ;;
        *) yellow "  - $phase (skipped)" ;;
    esac
done
exit $EXIT
