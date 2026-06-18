#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# ZION — Mesh (--features sovereign-aimp) cost benchmark  (issue #72)
#
# Measures the request-hot-path cost of the AIMP control-plane across three
# operating points, each as an RPS *delta* vs a clean default build. The
# point is not absolute throughput (that lives in bench-native.sh) but the
# marginal cost of compiling-in and turning-on the mesh.
#
# PROFILES (all hit the same API-GET hot path, TLS proxy -> Rust backend):
#   0. baseline     — default build (no sovereign-aimp). The reference RPS.
#   1. idle         — sovereign-aimp built, [sovereign_aimp].enabled = false.
#                     Confirms the gate is a single Option::is_some() check.
#                     Acceptance: delta < 1%.
#   2. lookup       — enabled = true, peers = []. Exercises the always-on
#                     per-request lookup() (X-Zion-Mesh-Score) with no gossip.
#                     Acceptance: delta < 3%.
#   3. mesh-active  — enabled = true, 3-node loopback mesh, anti-entropy at
#                     default 60s. Dispatcher pressure with a populated
#                     reputation map. Acceptance: delta < 5%.
#
# METHODOLOGY (mirrors bench-native.sh):
#   - 3s warmup, RUNS x DURs measurement, median primary, zero-error tolerance
#     (socket errors or Non-2xx fail the run).
#   - Deltas computed against the baseline median; the gates above are enforced
#     and a non-zero exit is returned if any profile regresses past its gate.
#
# This reproducer is the deliverable for #72; the numbers belong on a Linux
# host (the mesh UDP path + epoll behave closest to production there — see the
# e2e bench rig notes), but it runs end-to-end on macOS too.
# ============================================================================

export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

DUR=10
CONNS=100
THREADS=2
RUNS=5
WARMUP_SECS=3
COOLDOWN=5

# Acceptance gates (percent slower than baseline) per issue #72.
GATE_IDLE=1.0
GATE_LOOKUP=3.0
GATE_MESH=5.0

BACKEND_PORT=9090            # zion-bench-backend binds 0.0.0.0:9090 (fixed)
TLS_PORT=4480               # node-under-load HTTPS port
HTTP_PORT=8480
MESH_PORTS=(19443 19444 19445)   # loopback AIMP gossip ports for the 3 nodes

B="\033[1m" D="\033[2m" R="\033[0m"
CR="\033[31m" CC="\033[36m"
ts()  { date +%H:%M:%S; }
log() { printf "  ${D}%s${R} %b\n" "$(ts)" "$*"; }
die() { printf "  ${CR}FATAL${R} %b\n" "$*" >&2; cleanup; exit 1; }

PIDS=()
TMP="$(mktemp -d)"
cleanup() {
    for pid in "${PIDS[@]:-}"; do [[ -n "${pid:-}" ]] && kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    rm -rf "$TMP" 2>/dev/null || true
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }
need wrk; need curl; need nc; need python3

CERT="$PROJECT_DIR/benchmarks/certs/tls.crt"
KEY="$PROJECT_DIR/benchmarks/certs/tls.key"
[[ -f "$CERT" && -f "$KEY" ]] || bash "$PROJECT_DIR/benchmarks/certs/generate.sh" \
    || die "cert generation failed"

wait_for_https() {
    local i=0
    while ! curl -sk --max-time 2 "$1" >/dev/null 2>&1; do
        i=$((i+1)); [[ $i -ge 40 ]] && die "timeout waiting for $1"; sleep 0.5
    done
}

# ── wrk runner: echoes "rps|sock_errors|non2xx" ────────────────────────────
run_wrk() {
    local url=$1 out; out="$(mktemp)"
    wrk -t"$THREADS" -c"$CONNS" -d"${DUR}s" -H "Host: bench.local" --latency "$url" > "$out" 2>&1
    local rps sock non2xx
    rps=$(grep "Requests/sec:" "$out" | awk '{printf "%.1f", $2}')
    sock=$(grep "Socket errors" "$out" | awk '{print $4+$6+$8+$10}'); [[ -z "$sock" ]] && sock=0
    non2xx=$(grep "Non-2xx" "$out" | awk '{print $5}'); [[ -z "$non2xx" ]] && non2xx=0
    rm -f "$out"; echo "${rps:-0}|${sock}|${non2xx}"
}

# median of RUNS measurement runs for a URL; dies on any error response.
median_rps() {
    local url=$1 label=$2 vals=()
    curl -sk --max-time 2 "$url" >/dev/null 2>&1 || true
    sleep "$WARMUP_SECS"
    for ((r=1; r<=RUNS; r++)); do
        IFS='|' read -r rps sock non2xx <<< "$(run_wrk "$url")"
        [[ "$sock" -ne 0 || "$non2xx" -ne 0 ]] && \
            die "$label run $r had errors (sock=$sock non2xx=$non2xx) — zero-error tolerance"
        vals+=("$rps")
        log "    $label run $r: ${rps} rps"
    done
    python3 -c "import statistics,sys; print(f'{statistics.median([float(x) for x in sys.argv[1:]]):.1f}')" "${vals[@]}"
}

# ── build both flavours up front ───────────────────────────────────────────
build() {
    log "Building default (baseline) binary..."
    ( cd "$PROJECT_DIR" && cargo build --release --bin zion >/dev/null 2>&1 ) || die "default build failed"
    cp "$PROJECT_DIR/target/release/zion" "$TMP/zion-default"
    log "Building --features sovereign-aimp binary..."
    ( cd "$PROJECT_DIR" && cargo build --release --features sovereign-aimp --bin zion >/dev/null 2>&1 ) \
        || die "sovereign-aimp build failed"
    cp "$PROJECT_DIR/target/release/zion" "$TMP/zion-mesh"
}

start_backend() {
    ( cd "$PROJECT_DIR/benchmarks/backend" && cargo build --release >/dev/null 2>&1 ) || die "backend build failed"
    "$PROJECT_DIR/benchmarks/backend/target/release/zion-bench-backend" >/dev/null 2>&1 &
    PIDS+=("$!")
    local i=0; while ! nc -z 127.0.0.1 "$BACKEND_PORT" 2>/dev/null; do
        i=$((i+1)); [[ $i -ge 40 ]] && die "backend never came up on :$BACKEND_PORT"; sleep 0.25; done
}

# write_cfg <path> <https_port> <mesh_block>
write_cfg() {
    cat > "$1" <<TOML
[server]
listen_http = "127.0.0.1:${HTTP_PORT}"
listen_https = "127.0.0.1:${2}"

[tls]
cert_path = "${CERT}"
key_path = "${KEY}"
hot_reload = false

[upstreams]
backend = "http://127.0.0.1:${BACKEND_PORT}"

[[route]]
path = "/{*rest}"
upstream = "backend"
mode = "standard"
waf = false
${3:-}
TOML
}

# start_zion <binary> <config> <https_port>
start_zion() {
    ZION_CONFIG="$2" "$1" >/dev/null 2>&1 &
    PIDS+=("$!")
    wait_for_https "https://127.0.0.1:${3}/api/v1/data"
}

stop_last_zion() {
    local pid="${PIDS[-1]}"
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    sleep 1
}

URL="https://127.0.0.1:${TLS_PORT}/api/v1/data"

printf "\n${B}${CC}ZION mesh-cost benchmark (#72)${R}\n"
printf "  ${D}API-GET hot path - %d conns - %d threads - %dx%ds - gates idle<%s%% lookup<%s%% mesh<%s%%${R}\n\n" \
    "$CONNS" "$THREADS" "$RUNS" "$DUR" "$GATE_IDLE" "$GATE_LOOKUP" "$GATE_MESH"

build
start_backend

# ── Profile 0: baseline (default build) ────────────────────────────────────
log "${B}profile 0 — baseline (default build)${R}"
write_cfg "$TMP/cfg-baseline.toml" "$TLS_PORT"
start_zion "$TMP/zion-default" "$TMP/cfg-baseline.toml" "$TLS_PORT"
BASE=$(median_rps "$URL" "baseline")
stop_last_zion
log "baseline median: ${B}${BASE} rps${R}"
sleep "$COOLDOWN"

# ── Profile 1: idle (built, disabled) ──────────────────────────────────────
log "${B}profile 1 — idle (built, disabled)${R}"
write_cfg "$TMP/cfg-idle.toml" "$TLS_PORT" "
[sovereign_aimp]
enabled = false"
start_zion "$TMP/zion-mesh" "$TMP/cfg-idle.toml" "$TLS_PORT"
IDLE=$(median_rps "$URL" "idle")
stop_last_zion
sleep "$COOLDOWN"

# ── Profile 2: lookup-active (enabled, no peers) ───────────────────────────
log "${B}profile 2 — lookup-active (enabled, peers=[])${R}"
write_cfg "$TMP/cfg-lookup.toml" "$TLS_PORT" "
[sovereign_aimp]
enabled = true
listen = \"127.0.0.1:${MESH_PORTS[0]}\"
peers = []
identity_path = \"$TMP/id0.bin\""
start_zion "$TMP/zion-mesh" "$TMP/cfg-lookup.toml" "$TLS_PORT"
LOOKUP=$(median_rps "$URL" "lookup")
stop_last_zion
sleep "$COOLDOWN"

# ── Profile 3: mesh-active (3-node loopback mesh) ──────────────────────────
log "${B}profile 3 — mesh-active (3-node loopback mesh)${R}"
# Two gossip-peer nodes (sinks) point back at node 0; only node 0 is load-tested.
for n in 1 2; do
    write_cfg "$TMP/cfg-peer$n.toml" "$((TLS_PORT + n))" "
[sovereign_aimp]
enabled = true
listen = \"127.0.0.1:${MESH_PORTS[$n]}\"
peers = [\"127.0.0.1:${MESH_PORTS[0]}\"]
identity_path = \"$TMP/id$n.bin\"
anti_entropy_secs = 60"
    ZION_CONFIG="$TMP/cfg-peer$n.toml" "$TMP/zion-mesh" >/dev/null 2>&1 &
    PIDS+=("$!")
done
write_cfg "$TMP/cfg-mesh.toml" "$TLS_PORT" "
[sovereign_aimp]
enabled = true
listen = \"127.0.0.1:${MESH_PORTS[0]}\"
peers = [\"127.0.0.1:${MESH_PORTS[1]}\", \"127.0.0.1:${MESH_PORTS[2]}\"]
identity_path = \"$TMP/id0.bin\"
anti_entropy_secs = 60"
start_zion "$TMP/zion-mesh" "$TMP/cfg-mesh.toml" "$TLS_PORT"
sleep 3   # let the gossip loop settle
MESH=$(median_rps "$URL" "mesh-active")
sleep "$COOLDOWN"

# ── Report + gate enforcement ──────────────────────────────────────────────
printf "\n${B}Results (median RPS, delta vs baseline):${R}\n"
python3 - "$BASE" "$IDLE" "$LOOKUP" "$MESH" "$GATE_IDLE" "$GATE_LOOKUP" "$GATE_MESH" <<'PY'
import sys
base, idle, lookup, mesh = map(float, sys.argv[1:5])
g_idle, g_lookup, g_mesh = map(float, sys.argv[5:8])
def row(name, val, gate):
    delta = (base - val) / base * 100.0   # positive = slower than baseline
    ok = delta <= gate
    print(f"  {name:<14} {val:>10.1f} rps   {delta:+6.2f}%   gate<{gate}%   [{'PASS' if ok else 'FAIL'}]")
    return ok
print(f"  {'baseline':<14} {base:>10.1f} rps")
ok = True
ok &= row("idle",        idle,   g_idle)
ok &= row("lookup",      lookup, g_lookup)
ok &= row("mesh-active", mesh,   g_mesh)
print()
print("  All mesh-cost gates met." if ok else "  One or more profiles regressed past its gate.")
sys.exit(0 if ok else 1)
PY
