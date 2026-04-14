#!/usr/bin/env bash
# Zion PGO (Profile-Guided Optimization) Build Pipeline
#
# Two-phase build:
#   Phase 1: Build instrumented binary, run benchmark to collect profiles
#   Phase 2: Rebuild with profiles → 10-20% throughput improvement
#
# Requirements: Rust nightly or stable with PGO support, llvm-profdata
# Usage: bash benchmarks/bench-pgo.sh

set -euo pipefail
cd "$(dirname "$0")/.."

PGO_DIR="/tmp/zion-pgo"
MERGED_PROF="${PGO_DIR}/merged.profdata"

echo "┌─────────────────────────────────────────┐"
echo "│  ZION PGO BUILD PIPELINE                │"
echo "└─────────────────────────────────────────┘"

# Clean previous profiles
rm -rf "$PGO_DIR"
mkdir -p "$PGO_DIR"

# Phase 1: Instrumented build
echo ""
echo "Phase 1: Building instrumented binary..."
RUSTFLAGS="-Cprofile-generate=${PGO_DIR}" cargo build --release 2>&1 | tail -3

echo "Phase 1: Running benchmark workload to collect profiles..."
# Start Go backend
(cd benchmarks/backend && go run test-server.go &)
BACKEND_PID=$!
sleep 1

# Start instrumented Zion
ZION_CONFIG=benchmarks/zion-bench-tls.toml ./target/release/zion &
ZION_PID=$!
sleep 2

# Generate representative traffic (30s across multiple endpoints)
echo "  Generating traffic (30s)..."
wrk -c 50 -d 10s -t 4 --timeout 5s -H "Host: bench.local" \
    "https://127.0.0.1:4430/api/v1/data" 2>/dev/null | tail -2
wrk -c 50 -d 10s -t 4 --timeout 5s -H "Host: bench.local" \
    "https://127.0.0.1:4430/_next/static/js/app.js" 2>/dev/null | tail -2
wrk -c 50 -d 10s -t 4 --timeout 5s -H "Host: bench.local" \
    "https://127.0.0.1:4430/page" 2>/dev/null | tail -2

# Stop servers
kill "$ZION_PID" 2>/dev/null || true
kill "$BACKEND_PID" 2>/dev/null || true
wait "$ZION_PID" 2>/dev/null || true
wait "$BACKEND_PID" 2>/dev/null || true
sleep 1

# Merge profiles
echo ""
echo "Phase 1: Merging profiles..."
PROFDATA=$(which llvm-profdata 2>/dev/null || xcrun -f llvm-profdata 2>/dev/null || echo "")
if [[ -z "$PROFDATA" ]]; then
    echo "ERROR: llvm-profdata not found. Install LLVM tools or Xcode."
    echo "  macOS: xcode-select --install"
    echo "  Linux: apt install llvm"
    exit 1
fi

"$PROFDATA" merge -o "$MERGED_PROF" "${PGO_DIR}"/*.profraw
PROF_COUNT=$(ls "${PGO_DIR}"/*.profraw 2>/dev/null | wc -l | tr -d ' ')
echo "  Merged ${PROF_COUNT} profile files → ${MERGED_PROF}"

# Phase 2: Optimized build
echo ""
echo "Phase 2: Building PGO-optimized binary..."
RUSTFLAGS="-Cprofile-use=${MERGED_PROF} -Cllvm-args=-pgo-warn-missing-function" \
    cargo build --release 2>&1 | tail -3

BINARY_SIZE=$(ls -lh target/release/zion | awk '{print $5}')
echo ""
echo "┌─────────────────────────────────────────┐"
echo "│  PGO BUILD COMPLETE                     │"
echo "│  Binary: target/release/zion (${BINARY_SIZE})    │"
echo "│  Profile: ${MERGED_PROF}                │"
echo "│                                         │"
echo "│  Run bench-native.sh to measure delta   │"
echo "└─────────────────────────────────────────┘"
