#!/usr/bin/env bash
# =============================================================================
# Zion edge baseline harness — reproducible benchmark + RFC-conformance run.
#
# Produces a tracked PDF report (zion-<version>-baseline.pdf) from a clean
# checkout. Everything is pinned: tool params, lab config, upstream backend.
# Re-running on the same hardware reproduces the numbers within noise; the
# methodology (commands, versions, env) is captured verbatim in the report.
#
# Usage:   bash benchmarks/baseline/run-baseline.sh
# From:    repo root (the script cd's there regardless).
#
# Requires (versions are recorded into the report, not enforced):
#   cargo, go, openssl, jq, python3
#   benchmark:  oha, h2load (nghttp2), wrk
#   compliance: h2spec (env H2SPEC=/path or on PATH or ~/http-tools/h2spec),
#               testssl.sh
#   report:     python3 + weasyprint  (pip install weasyprint)
#
# macOS install hint:
#   brew install oha nghttp2 wrk testssl jq weasyprint
#   h2spec: https://github.com/summerwind/h2spec/releases  -> ~/http-tools/
# =============================================================================
set -euo pipefail

# ── Pinned parameters (single source of truth) ──────────────────────────────
DURATION="${DURATION:-20s}"        # oha / wrk wall-clock per run
CONNS="${CONNS:-50}"               # concurrent connections
WRK_THREADS="${WRK_THREADS:-4}"
H2LOAD_N="${H2LOAD_N:-200000}"     # total requests
H2LOAD_M="${H2LOAD_M:-20}"         # concurrent streams per connection
WARMUP="${WARMUP:-50}"             # cache-priming requests before measuring

HTTPS="https://127.0.0.1:4432"
URL_CACHE="$HTTPS/_next/static/chunk.js"   # static_cache route (RAM hit)
URL_PROXY="$HTTPS/api/v1/data"             # standard route (proxy passthrough)
HOSTPORT="127.0.0.1:4432"

# ── Locate repo root + workspace ────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"
RES="$SCRIPT_DIR/results"
rm -rf "$RES"; mkdir -p "$RES"

H2SPEC_BIN="${H2SPEC:-$(command -v h2spec || echo "$HOME/http-tools/h2spec")}"

log() { printf '\033[1;36m▶ %s\033[0m\n' "$*"; }
die() { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# ── Preflight: required tools ───────────────────────────────────────────────
for t in cargo go openssl jq python3 oha h2load wrk testssl.sh; do
  command -v "$t" >/dev/null 2>&1 || die "missing required tool: $t (see header for install hints)"
done
[ -x "$H2SPEC_BIN" ] || die "h2spec not found/executable: set H2SPEC=/path/to/h2spec"
command -v weasyprint >/dev/null 2>&1 || die "weasyprint CLI missing: brew install weasyprint (or pipx install weasyprint)"

# ── Build zion (release) + backend, generate certs ──────────────────────────
log "building zion (release)"
cargo build --release >/dev/null 2>&1 || die "zion release build failed"
ZION_BIN="$REPO_ROOT/target/release/zion"

log "generating self-signed certs (if absent)"
bash benchmarks/certs/generate.sh >/dev/null 2>&1 || true
[ -f benchmarks/certs/tls.crt ] || die "cert generation failed"

# ── Record environment + tool versions ──────────────────────────────────────
log "recording environment"
{
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "git_sha=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  echo "git_dirty=$(test -n "$(git status --porcelain 2>/dev/null)" && echo yes || echo no)"
  echo "zion_version=$("$ZION_BIN" --version 2>&1 | head -1)"
  echo "os=$(uname -sr)"
  echo "arch=$(uname -m)"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "cpu=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
    echo "cores=$(sysctl -n hw.ncpu 2>/dev/null || echo unknown)"
    echo "mem_gb=$(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1024 / 1024 / 1024 ))"
  else
    echo "cpu=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo unknown)"
    echo "cores=$(nproc 2>/dev/null || echo unknown)"
    echo "mem_gb=$(( $(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0) / 1024 / 1024 ))"
  fi
  echo "tool_oha=$(oha --version 2>&1 | head -1)"
  echo "tool_h2load=$(h2load --version 2>&1 | head -1)"
  echo "tool_wrk=$(wrk --version 2>&1 | head -1 || true)"
  echo "tool_h2spec=$("$H2SPEC_BIN" --version 2>&1 | head -1)"
  echo "tool_testssl=$(testssl.sh --version 2>&1 | sed $'s/\x1b\\[[0-9;]*m//g' | grep -iE 'testssl.*version|version.*testssl' | head -1)"
  echo "tool_openssl=$(openssl version 2>&1)"
  echo "tool_go=$(go version 2>&1)"
  echo "params_duration=$DURATION"
  echo "params_conns=$CONNS"
  echo "params_wrk_threads=$WRK_THREADS"
  echo "params_h2load_n=$H2LOAD_N"
  echo "params_h2load_m=$H2LOAD_M"
} > "$RES/meta.env"

# ── Start backend + zion, ensure teardown ───────────────────────────────────
cleanup() {
  [ -n "${ZION_PID:-}" ] && kill "$ZION_PID" 2>/dev/null || true
  [ -n "${BE_PID:-}" ] && kill "$BE_PID" 2>/dev/null || true
  lsof -ti:9090,4432,8082 2>/dev/null | xargs kill -9 2>/dev/null || true
}
trap cleanup EXIT
lsof -ti:9090,4432,8082 2>/dev/null | xargs kill -9 2>/dev/null || true

log "starting bench backend (:9090)"
( cd benchmarks/backend && go run main.go ) > "$RES/backend.log" 2>&1 &
BE_PID=$!

log "starting zion (:4432 https, TLS1.2+)"
ZION_CONFIG="$SCRIPT_DIR/zion-lab.toml" "$ZION_BIN" > "$RES/zion.log" 2>&1 &
ZION_PID=$!

# Wait for readiness (zion TLS accepting + backend up)
for i in $(seq 1 30); do
  if curl -sk -o /dev/null --max-time 2 "$URL_PROXY" 2>/dev/null; then break; fi
  sleep 0.5
  [ "$i" = 30 ] && die "zion/backend did not become ready"
done
log "lab ready"

# ── Functional verification: the v0.4.2 cache fix (Age header) ──────────────
log "verifying Age header on cache hit"
curl -sk -o /dev/null "$URL_CACHE"   # prime
curl -sk -D - -o /dev/null "$URL_CACHE" > "$RES/verify-cache-hit.txt" 2>&1

# ── Compliance: HTTP/2 RFC 9113/7540 (h2spec) ───────────────────────────────
log "h2spec (HTTP/2 conformance)"
"$H2SPEC_BIN" -t -k -h 127.0.0.1 -p 4432 > "$RES/h2spec.txt" 2>&1 || true

# ── Compliance: TLS (testssl.sh) ────────────────────────────────────────────
log "testssl.sh (TLS conformance) — this is the slow one"
testssl.sh --quiet --color 0 --jsonfile "$RES/testssl.json" "$HOSTPORT" > "$RES/testssl.txt" 2>&1 || true

# ── Benchmark: warmup then measure ──────────────────────────────────────────
log "warmup ($WARMUP req)"
for _ in $(seq 1 "$WARMUP"); do curl -sk -o /dev/null "$URL_CACHE"; done

log "oha — cache-hit ($DURATION, c=$CONNS)"
oha -z "$DURATION" -c "$CONNS" --insecure --no-tui "$URL_CACHE" > "$RES/oha-cache.txt" 2>&1

log "oha — proxy passthrough ($DURATION, c=$CONNS)"
oha -z "$DURATION" -c "$CONNS" --insecure --no-tui "$URL_PROXY" > "$RES/oha-proxy.txt" 2>&1

log "h2load — HTTP/2 cache-hit (n=$H2LOAD_N c=$CONNS m=$H2LOAD_M)"
h2load -n "$H2LOAD_N" -c "$CONNS" -m "$H2LOAD_M" "$URL_CACHE" > "$RES/h2load-cache.txt" 2>&1

log "wrk — HTTP/1.1 cache-hit (t=$WRK_THREADS c=$CONNS $DURATION)"
wrk -t"$WRK_THREADS" -c"$CONNS" -d"$DURATION" "$URL_CACHE" > "$RES/wrk-cache.txt" 2>&1

# ── Generate the PDF report ─────────────────────────────────────────────────
log "building HTML report"
PDF_NAME="$(python3 "$SCRIPT_DIR/build-report.py" "$RES" "$SCRIPT_DIR" | tail -1)"
[ -n "$PDF_NAME" ] || die "report builder produced no output name"

log "rendering PDF ($PDF_NAME)"
weasyprint "$SCRIPT_DIR/report.html" "$SCRIPT_DIR/$PDF_NAME" 2>/dev/null \
  || die "weasyprint PDF render failed"

log "DONE — report at benchmarks/baseline/$PDF_NAME"
