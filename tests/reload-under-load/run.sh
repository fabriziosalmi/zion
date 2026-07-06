#!/usr/bin/env bash
# Reload-under-load harness — proves a config hot-swap under concurrent traffic
# drops NO in-flight connections. (Production-hardening item #3.)
#
# On a fleet you reload config often; the ArcSwap swap must be invisible to
# live traffic. This fires sustained concurrent requests at a real Zion while
# repeatedly triggering real config swaps, and asserts:
#   1. ZERO failed requests across the whole run (no reset / non-2xx / timeout).
#   2. The config generation actually advanced during the load — i.e. many real
#      atomic swaps happened WHILE traffic was flowing (not before/after it).
#
# The reload trigger is `POST /admin/reload`, which re-reads zion.toml and runs
# the SAME `reload_now` atomic swap the file watcher uses (skipping the file
# watcher's 2s debounce, so the test is deterministic). `reload_now` stores a
# freshly-built snapshot unconditionally, so every call is a genuine swap.
#
# Requirements: a release zion + the bench backend (built here or via ZION_BIN),
# curl, openssl, bash. No Docker.
#
#   ./tests/reload-under-load/run.sh
#
# Env: DURATION (s, default 15) · WORKERS (default 24) · RELOADS (default 30)
#      ZION_BIN / BACKEND_BIN — prebuilt binaries (CI builds them once).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DURATION="${DURATION:-15}"
WORKERS="${WORKERS:-24}"
RELOADS="${RELOADS:-30}"
HTTPS_PORT=4433
ADMIN_PORT=9180
BACKEND_PORT=9090

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    G=$'\033[32m'; R=$'\033[31m'; B=$'\033[1m'; N=$'\033[0m'
else G=""; R=""; B=""; N=""; fi
step() { printf '\n%s── %s%s\n' "$B" "$*" "$N"; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/zion-reload.XXXXXX")"
cleanup() {
    [ -f "$WORK/zion.pid" ] && kill "$(cat "$WORK/zion.pid")" 2>/dev/null || true
    [ -f "$WORK/be.pid" ] && kill "$(cat "$WORK/be.pid")" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# ── Binaries ──
ZION_BIN="${ZION_BIN:-$ROOT/target/release/zion}"
BACKEND_BIN="${BACKEND_BIN:-$ROOT/benchmarks/backend/target/release/zion-bench-backend}"
if [ ! -x "$ZION_BIN" ]; then
    step "building zion (release)"; (cd "$ROOT" && cargo build --release --bin zion)
fi
if [ ! -x "$BACKEND_BIN" ]; then
    step "building bench backend (release)"
    (cd "$ROOT" && cargo build --release --manifest-path benchmarks/backend/Cargo.toml)
fi

# ── Cert ──
step "self-signed cert"
( cd "$ROOT/benchmarks/certs" && bash generate.sh >/dev/null 2>&1 || true )
CERT="$ROOT/benchmarks/certs/tls.crt"; KEY="$ROOT/benchmarks/certs/tls.key"
[ -f "$CERT" ] && [ -f "$KEY" ] || { echo "cert generation failed"; exit 1; }

# ── Config: a WAF /api route + catch-all + the admin API for the reload trigger.
cat > "$WORK/zion.toml" <<EOF
[server]
listen_http  = "0.0.0.0:8080"
listen_https = "0.0.0.0:$HTTPS_PORT"

[tls]
cert_path  = "$CERT"
key_path   = "$KEY"
hot_reload = false

[upstreams]
backend = "http://127.0.0.1:$BACKEND_PORT"

[admin]
listen         = "127.0.0.1:$ADMIN_PORT"
auth           = "internal-ip"
rate_limit_rps = 500

[[route]]
path     = "/api/{*rest}"
upstream = "backend"
waf      = true

[[route]]
path     = "/{*rest}"
upstream = "backend"
EOF

step "starting bench backend (:$BACKEND_PORT) + zion (:$HTTPS_PORT, admin :$ADMIN_PORT)"
"$BACKEND_BIN" > "$WORK/backend.log" 2>&1 & echo $! > "$WORK/be.pid"; disown
ZION_CONFIG="$WORK/zion.toml" "$ZION_BIN" > "$WORK/zion.log" 2>&1 & echo $! > "$WORK/zion.pid"; disown

# ── Readiness ──
url="https://127.0.0.1:$HTTPS_PORT/api/v1/data"
for i in $(seq 1 30); do
    code="$(curl -sk -o /dev/null -w '%{http_code}' -m 2 "$url" 2>/dev/null || echo 000)"
    [ "$code" = 200 ] && { echo "ready after ${i}s"; break; }
    [ "$i" = 30 ] && { echo "::error::zion not ready"; tail -20 "$WORK/zion.log" >&2; exit 1; }
    sleep 1
done

gen() { # read zion_config_generation from /metrics
    curl -sk -m 3 "https://127.0.0.1:$HTTPS_PORT/metrics" 2>/dev/null \
        | awk '/^zion_config_generation /{print $2; exit}'
}
gen0="$(gen)"; gen0="${gen0:-0}"

# ── Load workers: each hammers the WAF route for DURATION, counting ok/fail.
# fail = curl transport error, HTTP 000, or any non-2xx (a swap must never
# surface a 5xx/reset/404 to an in-flight request).
worker() {
    local id="$1" ok=0 fail=0 code deadline
    deadline=$(( $(date +%s) + DURATION ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        code="$(curl -sk -o /dev/null -w '%{http_code}' -m 5 "$url" 2>/dev/null || echo 000)"
        if [ "${code:0:1}" = 2 ]; then ok=$((ok+1)); else fail=$((fail+1)); echo "$code" >> "$WORK/failcodes"; fi
    done
    echo "$ok $fail" > "$WORK/w$id"
}

step "load: $WORKERS workers × ${DURATION}s, with $RELOADS live config swaps"
worker_pids=()
for i in $(seq 1 "$WORKERS"); do worker "$i" & worker_pids+=("$!"); done

# ── Reload loop: real atomic swaps spaced across the load window.
sleep 1  # let traffic ramp
reload_ok=0
interval=$(awk "BEGIN{print ($DURATION-2)/$RELOADS}")
for _ in $(seq 1 "$RELOADS"); do
    rc="$(curl -s -o /dev/null -w '%{http_code}' -m 3 -X POST "http://127.0.0.1:$ADMIN_PORT/admin/reload" 2>/dev/null || echo 000)"
    [ "${rc:0:1}" = 2 ] && reload_ok=$((reload_ok+1))
    sleep "$interval"
done
# Wait for the LOAD WORKERS only — a bare `wait` would also block on the
# backend/zion background daemons, which never exit.
wait "${worker_pids[@]}"

gen1="$(gen)"; gen1="${gen1:-0}"

# ── Tally ──
total_ok=0; total_fail=0
for i in $(seq 1 "$WORKERS"); do
    read -r o f < "$WORK/w$i" 2>/dev/null || { o=0; f=0; }
    total_ok=$((total_ok + o)); total_fail=$((total_fail + f))
done
swaps=$(( gen1 - gen0 ))

step "result"
printf '  requests: %s ok, %s%s failed%s\n' "$total_ok" \
    "$([ "$total_fail" -gt 0 ] && printf '%s' "$R")" "$total_fail" "$N"
printf '  config swaps during load: %s (generation %s → %s); admin reloads acked: %s/%s\n' \
    "$swaps" "$gen0" "$gen1" "$reload_ok" "$RELOADS"

fail=0
if [ "$total_fail" -ne 0 ]; then
    echo "  ${R}${B}FAIL${N} — $total_fail request(s) dropped/errored during config swaps:"
    sort "$WORK/failcodes" 2>/dev/null | uniq -c | sed 's/^/    /' >&2
    fail=1
fi
# A swap must have actually happened concurrently with traffic, else the test
# proves nothing. Require a healthy fraction of the reloads to have landed.
min_swaps=$(( RELOADS / 2 ))
if [ "$swaps" -lt "$min_swaps" ]; then
    echo "  ${R}${B}FAIL${N} — only $swaps swaps observed (< $min_swaps); reloads didn't run under load"
    fail=1
fi
if [ "$fail" -eq 0 ]; then
    echo "  ${G}${B}PASS${N} — $total_ok requests, 0 dropped across $swaps live config swaps."
fi
exit "$fail"
