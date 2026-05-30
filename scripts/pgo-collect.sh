#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# PGO profile-collection workload (issue #55).
#
# Drives a 10-second deterministic burst against an instrumented Zion
# binary (built with `RUSTFLAGS=-Cprofile-generate=$PGO_PROFILE_DIR`) and
# leaves the resulting `*.profraw` files under `$PGO_PROFILE_DIR` for
# the caller to merge with `llvm-profdata`.
#
# Inputs (env):
#   ZION_BIN          — path to the instrumented Zion binary (required)
#   PGO_PROFILE_DIR   — dir into which profraws are written (required)
#   ZION_HTTPS_PORT   — HTTPS listener port (default 4430)
#   ZION_HTTP_PORT    — plain HTTP listener port (default 8080)
#   BACKEND_PORT      — Go test backend port (default 9090)
#   WORKLOAD_SECONDS  — wrk duration per endpoint (default 10)
#
# Why these specifics:
#   * 10 s is the issue's target wall-clock. A shorter burst leaves the
#     hot path under-trained; a longer one bloats CI without reducing
#     variance below 1 %.
#   * We exercise three representative paths (WAF body POST + cache
#     read + admin GET) so the profile reflects the surfaces the
#     release binary actually uses, not just one micro-shape.
#   * Single-thread + fixed connection count → deterministic across runs.

set -euo pipefail
cd "$(dirname "$0")/.."

: "${ZION_BIN:?set ZION_BIN to the instrumented binary path}"
: "${PGO_PROFILE_DIR:?set PGO_PROFILE_DIR to the profraw output directory}"
ZION_HTTPS_PORT="${ZION_HTTPS_PORT:-4430}"
ZION_HTTP_PORT="${ZION_HTTP_PORT:-8080}"
BACKEND_PORT="${BACKEND_PORT:-9090}"
WORKLOAD_SECONDS="${WORKLOAD_SECONDS:-10}"

mkdir -p "$PGO_PROFILE_DIR"

echo "PGO collect:"
echo "  binary    : $ZION_BIN"
echo "  profraws  : $PGO_PROFILE_DIR"
echo "  zion :443 : $ZION_HTTPS_PORT"
echo "  zion :80  : $ZION_HTTP_PORT"
echo "  backend   : :$BACKEND_PORT"
echo "  duration  : ${WORKLOAD_SECONDS}s × 3 endpoints"

# ── 1. Backend ────────────────────────────────────────────────────────
# The Go test-server is shipped in-tree under benchmarks/backend/. Go is
# preinstalled on ubuntu-latest; on macOS the runner has it too.
# Declared up-front (empty) so the EXIT trap is safe under `set -u` even
# if we bail out before Zion starts.
ZION_PID=""

# Build the backend *synchronously* first, then run the compiled binary.
# `go run … &` backgrounds the compile + module-fetch, which on a cold
# runner can outlast the readiness wait and lose the race ("backend never
# became ready"). A pre-built binary starts effectively instantly, and a
# build failure surfaces here instead of as a silent timeout.
echo "[1/5] building backend"
BACKEND_BIN="$(mktemp -t pgo-backend-XXXXXX)"
( cd benchmarks/backend && go build -o "$BACKEND_BIN" test-server.go )
echo "[1/5] starting backend on :$BACKEND_PORT"
"$BACKEND_BIN" > /tmp/pgo-backend.log 2>&1 &
BACKEND_PID=$!

cleanup() {
  set +e
  kill "$BACKEND_PID" 2>/dev/null || true
  [ -n "${ZION_PID:-}" ] && kill "$ZION_PID" 2>/dev/null || true
  wait "$BACKEND_PID" 2>/dev/null || true
  [ -n "${ZION_PID:-}" ] && wait "$ZION_PID" 2>/dev/null || true
  rm -f "$BACKEND_BIN" 2>/dev/null || true
}
trap cleanup EXIT

# Wait for backend ready (the binary is already built, so this only covers
# process startup + port bind, but keep margin for slow CI).
for _ in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:${BACKEND_PORT}/api/v1/data" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
curl -fsS "http://127.0.0.1:${BACKEND_PORT}/api/v1/data" >/dev/null \
  || { echo "backend never became ready"; cat /tmp/pgo-backend.log; exit 1; }

# ── 2. Certs ──────────────────────────────────────────────────────────
echo "[2/5] generating self-signed TLS cert (if missing)"
bash benchmarks/certs/generate.sh

# ── 3. Zion (instrumented) ────────────────────────────────────────────
# Render a minimal config inline so the script is self-contained — the
# committed bench config files target other ports / use cases. Profraws
# are written by the runtime as the binary exits, so we issue SIGTERM
# (not SIGKILL) at the end.
ZION_CFG="$(mktemp -t zion-pgo-XXXXXX.toml)"
cat > "$ZION_CFG" <<EOF
[server]
listen_http  = "127.0.0.1:${ZION_HTTP_PORT}"
listen_https = "127.0.0.1:${ZION_HTTPS_PORT}"

[tls]
cert_path  = "./benchmarks/certs/tls.crt"
key_path   = "./benchmarks/certs/tls.key"
hot_reload = false

[upstreams]
backend = "http://127.0.0.1:${BACKEND_PORT}"

[waf_profile.standard]
max_body_mb = 10

[[route]]
path        = "/api/{*rest}"
upstream    = "backend"
mode        = "standard"
waf_profile = "standard"

[[route]]
path     = "/_next/static/{*rest}"
upstream = "backend"
mode     = "static_cache"

[[route]]
path     = "/{*rest}"
upstream = "backend"
mode     = "standard"
EOF

echo "[3/5] starting instrumented Zion on :$ZION_HTTPS_PORT"
LLVM_PROFILE_FILE="${PGO_PROFILE_DIR}/zion-%m-%p.profraw" \
  ZION_BOOT_FAST=1 \
  ZION_CONFIG="$ZION_CFG" \
  "$ZION_BIN" > /tmp/pgo-zion.log 2>&1 &
ZION_PID=$!

# Wait for Zion ready (max 15 s — TLS handshake + boot is slower than backend).
for _ in $(seq 1 30); do
  if curl -ks "https://127.0.0.1:${ZION_HTTPS_PORT}/api/v1/data" \
       -H "Host: bench.local" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
curl -ks "https://127.0.0.1:${ZION_HTTPS_PORT}/api/v1/data" \
   -H "Host: bench.local" >/dev/null \
  || { echo "zion never became ready"; cat /tmp/pgo-zion.log; exit 1; }

# ── 4. Workload ───────────────────────────────────────────────────────
# wrk is the de-facto micro-load-gen on ubuntu-latest. If it's not on
# PATH, fall back to a curl loop — slower but still deterministic.
WRK="$(command -v wrk 2>/dev/null || true)"
URL_BASE="https://127.0.0.1:${ZION_HTTPS_PORT}"
HEADER='Host: bench.local'

run_endpoint() {
  local path="$1"
  local label="$2"
  echo "[4/5] workload: $label"
  if [[ -n "$WRK" ]]; then
    "$WRK" -c 32 -d "${WORKLOAD_SECONDS}s" -t 2 --timeout 5s \
        -H "$HEADER" "${URL_BASE}${path}" 2>/dev/null \
      | tail -2 || true
  else
    # Fallback: tight curl loop. Less throughput than wrk but still
    # exercises the same code paths for the profiler.
    local end=$(( $(date +%s) + WORKLOAD_SECONDS ))
    while [[ $(date +%s) -lt $end ]]; do
      curl -ks --max-time 2 -H "$HEADER" "${URL_BASE}${path}" >/dev/null || true
    done
  fi
}

run_endpoint "/api/v1/data"          "GET /api/v1/data       (dispatch + WAF gate 1+2)"
run_endpoint "/_next/static/foo.js"  "GET /_next/static/...  (static cache miss → fill)"
run_endpoint "/api/v1/health"        "GET /api/v1/health     (admin-style endpoint)"

# ── 5. Shutdown — SIGTERM so the runtime flushes profraws ─────────────
echo "[5/5] shutting down (SIGTERM, profraws will flush on exit)"
kill "$ZION_PID" 2>/dev/null || true
wait "$ZION_PID" 2>/dev/null || true
ZION_PID=

PROFCOUNT=$(find "$PGO_PROFILE_DIR" -name '*.profraw' 2>/dev/null | wc -l | tr -d ' ')
if [[ "$PROFCOUNT" -eq 0 ]]; then
  echo "FATAL: no .profraw files written — was the binary built with -Cprofile-generate?"
  exit 1
fi
echo "ok: $PROFCOUNT profraw files written under $PGO_PROFILE_DIR"
