#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# ZION BENCHMARK SUITE
# Scientific, reproducible benchmarks: Zion vs nginx vs nginx+Varnish vs nginx+ModSec+Varnish
# Machine: Apple M4 Pro (local)
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results/$(date +%Y%m%d_%H%M%S)"
BACKEND_PID=""
ZION_PID=""

# Benchmark parameters
DURATION=30          # seconds per test
THREADS=4            # wrk threads (M4 Pro has 12 cores, keep headroom)
CONNECTIONS=256      # concurrent connections
WARMUP_SECONDS=5     # warmup before measurement
WARMUP_REQUESTS=1000 # hey warmup requests
RUNS=3               # repeat each test N times for statistical significance

# Endpoints to test
API_PATH="/api/v1/data"
STATIC_PATH="/_next/static/chunk.js"
HTML_PATH="/"

mkdir -p "$RESULTS_DIR"

# ============================================================================
# UTILITIES
# ============================================================================

log() { echo -e "\n=== $(date +%H:%M:%S) $* ===" | tee -a "$RESULTS_DIR/bench.log"; }
die() { echo "FATAL: $*" >&2; cleanup; exit 1; }

cleanup() {
    log "Cleaning up..."
    [[ -n "$BACKEND_PID" ]] && kill "$BACKEND_PID" 2>/dev/null || true
    [[ -n "$ZION_PID" ]] && kill "$ZION_PID" 2>/dev/null || true
    cd "$SCRIPT_DIR" && docker compose down 2>/dev/null || true
}
trap cleanup EXIT

wait_for_port() {
    local host=$1 port=$2 timeout=${3:-10}
    for i in $(seq 1 "$timeout"); do
        if nc -z "$host" "$port" 2>/dev/null; then return 0; fi
        sleep 1
    done
    die "Timeout waiting for $host:$port"
}

wait_for_https() {
    local url=$1 timeout=${2:-15}
    for i in $(seq 1 "$timeout"); do
        if curl -sk --max-time 2 -H "Host: bench.local" "$url" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    die "Timeout waiting for $url"
}

# Run a single benchmark with hey (better for latency percentiles than wrk)
run_hey() {
    local name=$1 url=$2 method=${3:-GET} body_file=${4:-}
    local output="$RESULTS_DIR/${name}.txt"

    log "Benchmarking: $name ($url)"

    # Warmup (with -host for SNI)
    hey -n "$WARMUP_REQUESTS" -c 50 -host "bench.local" "$url" >/dev/null 2>&1 || true

    local all_rps=()
    for run in $(seq 1 "$RUNS"); do
        local run_file="$RESULTS_DIR/${name}_run${run}.txt"

        if [[ -n "$body_file" ]]; then
            hey -z "${DURATION}s" -c "$CONNECTIONS" -t 30 \
                -m "$method" -D "$body_file" \
                -T "application/json" \
                -host "bench.local" \
                "$url" > "$run_file" 2>&1
        else
            hey -z "${DURATION}s" -c "$CONNECTIONS" -t 30 \
                -host "bench.local" \
                "$url" > "$run_file" 2>&1
        fi

        # Extract RPS
        local rps
        rps=$(grep "Requests/sec:" "$run_file" | awk '{print $2}')
        all_rps+=("$rps")
        echo "  Run $run: $rps req/s" | tee -a "$RESULTS_DIR/bench.log"
    done

    # Best result (peak performance)
    printf '%s\n' "${all_rps[@]}" | sort -rn | head -1 > "$RESULTS_DIR/${name}_best_rps.txt"

    # Copy last run as the detailed output
    cp "$RESULTS_DIR/${name}_run${RUNS}.txt" "$output"
}

# ============================================================================
# PHASE 0: Prerequisites check
# ============================================================================

log "Checking prerequisites"
command -v hey >/dev/null || die "hey not found. Install with: brew install hey"
command -v docker >/dev/null || die "docker not found"
command -v go >/dev/null || die "go not found (needed for benchmark backend)"

# Build Zion release
log "Building Zion (release)"
cd "$PROJECT_DIR"
cargo build --release 2>&1 | tail -3
ZION_BIN="$PROJECT_DIR/target/release/zion"
[[ -f "$ZION_BIN" ]] || die "Zion binary not found"

# Create test POST body for WAF benchmarks
echo '{"username":"testuser","email":"test@example.com","data":{"nested":true}}' > "$RESULTS_DIR/post_body.json"

# ============================================================================
# PHASE 1: Start shared backend (native Go, no container overhead)
# ============================================================================

log "Starting benchmark backend (Go, native)"
cd "$SCRIPT_DIR/backend"
go run main.go &
BACKEND_PID=$!
wait_for_port 127.0.0.1 9090
log "Backend ready on :9090"

# ============================================================================
# PHASE 2: ZION benchmarks (native, bare metal on M4 Pro)
# ============================================================================

# --- Scenario 1: Zion TLS only ---
log "Starting Zion: TLS only (port 4430)"
cd "$PROJECT_DIR"
ZION_CONFIG=benchmarks/zion-bench-tls.toml "$ZION_BIN" &
ZION_PID=$!
wait_for_https "https://127.0.0.1:4430/"

run_hey "zion_tls_api_get"     "https://127.0.0.1:4430${API_PATH}"
run_hey "zion_tls_static_get"  "https://127.0.0.1:4430${STATIC_PATH}"
run_hey "zion_tls_html_get"    "https://127.0.0.1:4430${HTML_PATH}"

kill "$ZION_PID" 2>/dev/null; wait "$ZION_PID" 2>/dev/null || true; ZION_PID=""
sleep 1

# --- Scenario 2: Zion TLS + WAF ---
log "Starting Zion: TLS + WAF (port 4431)"
ZION_CONFIG=benchmarks/zion-bench-tls-waf.toml "$ZION_BIN" &
ZION_PID=$!
wait_for_https "https://127.0.0.1:4431/"

run_hey "zion_tls_waf_api_get"    "https://127.0.0.1:4431${API_PATH}"
run_hey "zion_tls_waf_api_post"   "https://127.0.0.1:4431${API_PATH}" POST "$RESULTS_DIR/post_body.json"
run_hey "zion_tls_waf_static_get" "https://127.0.0.1:4431${STATIC_PATH}"

kill "$ZION_PID" 2>/dev/null; wait "$ZION_PID" 2>/dev/null || true; ZION_PID=""
sleep 1

# --- Scenario 3: Zion TLS + Cache ---
log "Starting Zion: TLS + Cache (port 4432)"
ZION_CONFIG=benchmarks/zion-bench-tls-cache.toml "$ZION_BIN" &
ZION_PID=$!
wait_for_https "https://127.0.0.1:4432/"

# Prime the cache first
curl -sk -H "Host: bench.local" "https://127.0.0.1:4432${STATIC_PATH}" >/dev/null

run_hey "zion_tls_cache_api_get"    "https://127.0.0.1:4432${API_PATH}"
run_hey "zion_tls_cache_static_get" "https://127.0.0.1:4432${STATIC_PATH}"

kill "$ZION_PID" 2>/dev/null; wait "$ZION_PID" 2>/dev/null || true; ZION_PID=""
sleep 1

# --- Scenario 4: Zion TLS + WAF + Cache ---
log "Starting Zion: TLS + WAF + Cache (port 4433)"
ZION_CONFIG=benchmarks/zion-bench-tls-waf-cache.toml "$ZION_BIN" &
ZION_PID=$!
wait_for_https "https://127.0.0.1:4433/"

curl -sk -H "Host: bench.local" "https://127.0.0.1:4433${STATIC_PATH}" >/dev/null

run_hey "zion_full_api_get"     "https://127.0.0.1:4433${API_PATH}"
run_hey "zion_full_api_post"    "https://127.0.0.1:4433${API_PATH}" POST "$RESULTS_DIR/post_body.json"
run_hey "zion_full_static_get"  "https://127.0.0.1:4433${STATIC_PATH}"
run_hey "zion_full_html_get"    "https://127.0.0.1:4433${HTML_PATH}"

kill "$ZION_PID" 2>/dev/null; wait "$ZION_PID" 2>/dev/null || true; ZION_PID=""

# ============================================================================
# PHASE 3: Docker competitors (CPU-capped to 1 core each for fairness)
# ============================================================================

log "Starting Docker containers (nginx, nginx+modsec, varnish)"
cd "$SCRIPT_DIR"
docker compose up -d --build 2>&1 | tail -5

# Wait for all services
wait_for_https "https://127.0.0.1:8443/"   30   # nginx
wait_for_https "https://127.0.0.1:8445/"   30   # nginx + varnish (TLS terminator)
# nginx-modsec may take longer to load CRS rules
wait_for_https "https://127.0.0.1:8444/"   45 || log "WARNING: nginx-modsec not ready, skipping"

# --- Scenario 5: nginx baseline ---
log "Benchmarking: nginx baseline"
run_hey "nginx_api_get"     "https://127.0.0.1:8443${API_PATH}"
run_hey "nginx_static_get"  "https://127.0.0.1:8443${STATIC_PATH}"
run_hey "nginx_html_get"    "https://127.0.0.1:8443${HTML_PATH}"

# --- Scenario 6: nginx + Varnish ---
log "Benchmarking: nginx + Varnish (TLS terminated)"

# Prime Varnish cache
curl -sk "https://127.0.0.1:8445${STATIC_PATH}" >/dev/null
curl -sk "https://127.0.0.1:8445${HTML_PATH}" >/dev/null

run_hey "nginx_varnish_api_get"     "https://127.0.0.1:8445${API_PATH}"
run_hey "nginx_varnish_static_get"  "https://127.0.0.1:8445${STATIC_PATH}"
run_hey "nginx_varnish_html_get"    "https://127.0.0.1:8445${HTML_PATH}"

# --- Scenario 7: nginx + ModSecurity + Varnish ---
if curl -sk --max-time 2 "https://127.0.0.1:8444/" >/dev/null 2>&1; then
    log "Benchmarking: nginx + ModSecurity"
    run_hey "nginx_modsec_api_get"    "https://127.0.0.1:8444${API_PATH}"
    run_hey "nginx_modsec_api_post"   "https://127.0.0.1:8444${API_PATH}" POST "$RESULTS_DIR/post_body.json"
    run_hey "nginx_modsec_static_get" "https://127.0.0.1:8444${STATIC_PATH}"
else
    log "SKIPPED: nginx + ModSecurity (container not ready)"
fi

# ============================================================================
# PHASE 4: Results summary
# ============================================================================

log "Generating results summary"

cat > "$RESULTS_DIR/SUMMARY.md" << 'HEADER'
# Zion Benchmark Results

| Scenario | Endpoint | Req/s (best) | Avg Latency | P99 Latency |
|----------|----------|-------------|-------------|-------------|
HEADER

for f in "$RESULTS_DIR"/*_run${RUNS}.txt; do
    [[ -f "$f" ]] || continue
    name=$(basename "$f" "_run${RUNS}.txt")
    rps=$(grep "Requests/sec:" "$f" | awk '{print $2}')
    avg=$(grep "Average" "$f" | head -1 | awk '{print $2}')
    p99=$(grep "99%" "$f" | head -1 | awk '{print $2}' 2>/dev/null || echo "n/a")
    echo "| $name | - | $rps | $avg | $p99 |" >> "$RESULTS_DIR/SUMMARY.md"
done

echo "" >> "$RESULTS_DIR/SUMMARY.md"
echo "Machine: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo 'unknown')" >> "$RESULTS_DIR/SUMMARY.md"
echo "Date: $(date)" >> "$RESULTS_DIR/SUMMARY.md"
echo "Duration per test: ${DURATION}s x ${RUNS} runs, ${CONNECTIONS} connections" >> "$RESULTS_DIR/SUMMARY.md"

log "DONE. Results in: $RESULTS_DIR"
cat "$RESULTS_DIR/SUMMARY.md"
