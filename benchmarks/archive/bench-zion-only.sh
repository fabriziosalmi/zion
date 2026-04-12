#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# ZION STANDALONE BENCHMARK
# Tests Zion in 4 configurations against its own Go backend.
# Uses `hey` for latency percentiles and req/s.
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results/$(date +%Y%m%d_%H%M%S)"
BACKEND_PID=""
ZION_PID=""

# Parameters
DURATION=15           # seconds per test
CONNECTIONS=256       # concurrent connections
WARMUP_REQUESTS=2000  # warmup before measurement
RUNS=3                # repeat for significance

mkdir -p "$RESULTS_DIR"

log() { echo -e "\n=== $(date +%H:%M:%S) $* ==="; }
die() { echo "FATAL: $*" >&2; cleanup; exit 1; }

cleanup() {
    [[ -n "$BACKEND_PID" ]] && kill "$BACKEND_PID" 2>/dev/null || true
    [[ -n "$ZION_PID" ]] && kill "$ZION_PID" 2>/dev/null || true
}
trap cleanup EXIT

wait_for_port() {
    local host=$1 port=$2
    for i in $(seq 1 10); do
        nc -z "$host" "$port" 2>/dev/null && return 0
        sleep 0.5
    done
    die "Timeout waiting for $host:$port"
}

wait_for_https() {
    local url=$1
    for i in $(seq 1 15); do
        curl -sk --max-time 2 "$url" >/dev/null 2>&1 && return 0
        sleep 0.5
    done
    die "Timeout waiting for $url"
}

# Run benchmark with hey, 3 runs, extract stats
run_bench() {
    local name=$1 url=$2 method=${3:-GET} body_file=${4:-}

    log "BENCH: $name"
    echo "  URL: $url  Method: $method  Conns: $CONNECTIONS  Duration: ${DURATION}s x $RUNS runs"

    # Warmup
    hey -n "$WARMUP_REQUESTS" -c 50 -host "bench.local" "$url" >/dev/null 2>&1 || true

    local best_rps=0
    for run in $(seq 1 "$RUNS"); do
        local outfile="$RESULTS_DIR/${name}_run${run}.txt"

        if [[ -n "$body_file" ]]; then
            hey -z "${DURATION}s" -c "$CONNECTIONS" -t 30 \
                -m "$method" -D "$body_file" \
                -T "application/json" \
                -host "bench.local" \
                "$url" > "$outfile" 2>&1
        else
            hey -z "${DURATION}s" -c "$CONNECTIONS" -t 30 \
                -host "bench.local" \
                "$url" > "$outfile" 2>&1
        fi

        local rps avg p50 p99
        rps=$(grep "Requests/sec:" "$outfile" | awk '{print $2}')
        avg=$(grep "Average" "$outfile" | head -1 | awk '{print $2}')
        p50=$(grep "50%" "$outfile" | head -1 | awk '{print $2}' 2>/dev/null || echo "n/a")
        p99=$(grep "99%" "$outfile" | head -1 | awk '{print $2}' 2>/dev/null || echo "n/a")

        printf "  Run %d: %10s req/s | avg=%s | p50=%s | p99=%s\n" "$run" "$rps" "$avg" "$p50" "$p99"

        # Track best
        if (( $(echo "$rps > $best_rps" | bc -l) )); then
            best_rps=$rps
            cp "$outfile" "$RESULTS_DIR/${name}_best.txt"
        fi
    done

    echo "$best_rps" > "$RESULTS_DIR/${name}_peak_rps.txt"
    echo "  PEAK: $best_rps req/s"
}

start_zion() {
    local config=$1 port=$2
    cd "$PROJECT_DIR"
    ZION_CONFIG="$config" ./target/release/zion 2>/dev/null &
    ZION_PID=$!
    wait_for_https "https://127.0.0.1:${port}/" || die "Zion failed to start"
}

stop_zion() {
    [[ -n "$ZION_PID" ]] && kill "$ZION_PID" 2>/dev/null && wait "$ZION_PID" 2>/dev/null || true
    ZION_PID=""
    sleep 0.5
}

# ============================================================================
# Pre-flight
# ============================================================================

log "PRE-FLIGHT CHECKS"
command -v hey >/dev/null || die "hey not found"
command -v go >/dev/null || die "go not found"
[[ -f "$PROJECT_DIR/target/release/zion" ]] || die "Build zion first: cargo build --release"

# POST body for WAF benchmarks
echo '{"username":"testuser","email":"test@example.com","data":{"nested":true}}' > "$RESULTS_DIR/post_body.json"

# ============================================================================
# Start backend
# ============================================================================

log "STARTING BACKEND (Go :9090)"
cd "$SCRIPT_DIR/backend"
go run main.go &
BACKEND_PID=$!
wait_for_port 127.0.0.1 9090
echo "  Backend ready."

# Verify backend works
curl -s http://127.0.0.1:9090/api/v1/data | head -c 80
echo ""

# ============================================================================
# SCENARIO 1: Zion TLS only
# ============================================================================

log "SCENARIO 1: TLS only (port 4430)"
start_zion "benchmarks/zion-bench-tls.toml" 4430

run_bench "zion_tls_api_get"    "https://127.0.0.1:4430/api/v1/data"
run_bench "zion_tls_static_get" "https://127.0.0.1:4430/_next/static/chunk.js"
run_bench "zion_tls_html_get"   "https://127.0.0.1:4430/"

stop_zion

# ============================================================================
# SCENARIO 2: Zion TLS + WAF
# ============================================================================

log "SCENARIO 2: TLS + WAF (port 4431)"
start_zion "benchmarks/zion-bench-tls-waf.toml" 4431

run_bench "zion_waf_api_get"    "https://127.0.0.1:4431/api/v1/data"
run_bench "zion_waf_api_post"   "https://127.0.0.1:4431/api/v1/data" POST "$RESULTS_DIR/post_body.json"
run_bench "zion_waf_static_get" "https://127.0.0.1:4431/_next/static/chunk.js"

stop_zion

# ============================================================================
# SCENARIO 3: Zion TLS + RAM Cache
# ============================================================================

log "SCENARIO 3: TLS + Cache (port 4432)"
start_zion "benchmarks/zion-bench-tls-cache.toml" 4432

# Prime cache
curl -sk -H "Host: bench.local" "https://127.0.0.1:4432/_next/static/chunk.js" >/dev/null
echo "  Cache primed."

run_bench "zion_cache_api_get"    "https://127.0.0.1:4432/api/v1/data"
run_bench "zion_cache_static_get" "https://127.0.0.1:4432/_next/static/chunk.js"

stop_zion

# ============================================================================
# SCENARIO 4: Zion FULL (TLS + WAF + Cache)
# ============================================================================

log "SCENARIO 4: FULL — TLS + WAF + Cache (port 4433)"
start_zion "benchmarks/zion-bench-tls-waf-cache.toml" 4433

curl -sk -H "Host: bench.local" "https://127.0.0.1:4433/_next/static/chunk.js" >/dev/null
echo "  Cache primed."

run_bench "zion_full_api_get"    "https://127.0.0.1:4433/api/v1/data"
run_bench "zion_full_api_post"   "https://127.0.0.1:4433/api/v1/data" POST "$RESULTS_DIR/post_body.json"
run_bench "zion_full_static_get" "https://127.0.0.1:4433/_next/static/chunk.js"
run_bench "zion_full_html_get"   "https://127.0.0.1:4433/"

stop_zion

# ============================================================================
# SUMMARY
# ============================================================================

log "RESULTS SUMMARY"
echo ""
printf "%-30s %12s %12s %12s %12s\n" "Test" "Req/s (peak)" "Avg Lat" "P50" "P99"
printf "%-30s %12s %12s %12s %12s\n" "------------------------------" "------------" "------------" "------------" "------------"

for f in "$RESULTS_DIR"/*_best.txt; do
    [[ -f "$f" ]] || continue
    name=$(basename "$f" "_best.txt")
    rps=$(grep "Requests/sec:" "$f" | awk '{print $2}')
    avg=$(grep "Average" "$f" | head -1 | awk '{print $2}')
    p50=$(grep "50%" "$f" | head -1 | awk '{print $2}' 2>/dev/null || echo "n/a")
    p99=$(grep "99%" "$f" | head -1 | awk '{print $2}' 2>/dev/null || echo "n/a")
    printf "%-30s %12s %12s %12s %12s\n" "$name" "$rps" "$avg" "$p50" "$p99"
done

echo ""
echo "Machine: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo 'unknown')"
echo "Date: $(date)"
echo "Config: ${DURATION}s x ${RUNS} runs, ${CONNECTIONS} concurrent connections"
echo "Results dir: $RESULTS_DIR"
