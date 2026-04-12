#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# ZION vs NGINX — Scientific Benchmark
# Identical test conditions for both proxies:
#   - Same backend (Go :9090, native)
#   - Same TLS cert, same TLS 1.3
#   - Same endpoints, same concurrency, same duration
#   - nginx via Docker (1 worker, no access log, keepalive 64)
#   - Zion native (release build, single process)
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results/vs_nginx_$(date +%Y%m%d_%H%M%S)"
BACKEND_PID=""
ZION_PID=""
NGINX_CONTAINER="zion-bench-nginx"

DURATION=15
CONNECTIONS=256
WARMUP=2000
RUNS=3

ENDPOINTS=(
    "api_get|/api/v1/data|GET|"
    "static_get|/_next/static/chunk.js|GET|"
    "html_get|/|GET|"
    "api_post|/api/v1/data|POST|post_body.json"
)

mkdir -p "$RESULTS_DIR"

log() { echo -e "\n$(date +%H:%M:%S) >>> $*"; }
die() { echo "FATAL: $*" >&2; cleanup; exit 1; }

cleanup() {
    [[ -n "$ZION_PID" ]] && kill "$ZION_PID" 2>/dev/null || true
    [[ -n "$BACKEND_PID" ]] && kill "$BACKEND_PID" 2>/dev/null || true
    docker rm -f "$NGINX_CONTAINER" 2>/dev/null || true
}
trap cleanup EXIT

wait_for_port() {
    for _ in $(seq 1 20); do nc -z "$1" "$2" 2>/dev/null && return 0; sleep 0.5; done
    die "Timeout: $1:$2"
}

wait_for_https() {
    for _ in $(seq 1 30); do curl -sk --max-time 2 "$1" >/dev/null 2>&1 && return 0; sleep 0.5; done
    die "Timeout: $1"
}

run_hey() {
    local name=$1 url=$2 method=${3:-GET} body=${4:-}
    local best_rps=0

    hey -n "$WARMUP" -c 50 -host "bench.local" "$url" >/dev/null 2>&1 || true

    for run in $(seq 1 "$RUNS"); do
        local out="$RESULTS_DIR/${name}_run${run}.txt"
        if [[ -n "$body" && -f "$RESULTS_DIR/$body" ]]; then
            hey -z "${DURATION}s" -c "$CONNECTIONS" -t 30 \
                -m "$method" -D "$RESULTS_DIR/$body" -T "application/json" \
                -host "bench.local" "$url" > "$out" 2>&1
        else
            hey -z "${DURATION}s" -c "$CONNECTIONS" -t 30 \
                -host "bench.local" "$url" > "$out" 2>&1
        fi

        local rps
        rps=$(grep "Requests/sec:" "$out" | awk '{print $2}')
        if (( $(echo "${rps:-0} > $best_rps" | bc -l) )); then
            best_rps=$rps
            cp "$out" "$RESULTS_DIR/${name}_best.txt"
        fi
        printf "    run %d: %.0f req/s\n" "$run" "$rps"
    done
    echo "$best_rps" > "$RESULTS_DIR/${name}_peak.txt"
    printf "    PEAK: %.0f req/s\n" "$best_rps"
}

# ============================================================================

log "PRE-FLIGHT"
command -v hey >/dev/null || die "hey not found"
command -v docker >/dev/null || die "docker not found"
command -v go >/dev/null || die "go not found"
[[ -f "$PROJECT_DIR/target/release/zion" ]] || die "cargo build --release first"

echo '{"username":"testuser","email":"test@example.com","data":{"nested":true}}' > "$RESULTS_DIR/post_body.json"

# ============================================================================
# BACKEND
# ============================================================================

log "STARTING BACKEND (Go :9090)"
cd "$SCRIPT_DIR/backend" && go run main.go &
BACKEND_PID=$!
wait_for_port 127.0.0.1 9090
log "Backend ready"

# ============================================================================
# NGINX (Docker, 1 worker, access_log off)
# ============================================================================

log "STARTING NGINX (Docker, port 8443)"
docker rm -f "$NGINX_CONTAINER" 2>/dev/null || true
docker run -d --name "$NGINX_CONTAINER" \
    -p 8443:443 \
    -v "$SCRIPT_DIR/nginx-native-bench.conf:/etc/nginx/nginx.conf:ro" \
    -v "$SCRIPT_DIR/certs:/etc/ssl/bench:ro" \
    nginx:1.27-alpine
wait_for_https "https://127.0.0.1:8443/"
log "nginx ready on :8443"

# Verify nginx reaches backend
curl -sk -H "Host: bench.local" https://127.0.0.1:8443/api/v1/data | head -c 40
echo ""

for ep in "${ENDPOINTS[@]}"; do
    IFS='|' read -r label path method body <<< "$ep"
    log "NGINX: $label ($method $path)"
    run_hey "nginx_${label}" "https://127.0.0.1:8443${path}" "$method" "$body"
done

docker rm -f "$NGINX_CONTAINER" 2>/dev/null || true
sleep 1

# ============================================================================
# ZION — 3 configs: TLS only, TLS+WAF, TLS+WAF+Cache
# ============================================================================

run_zion_scenario() {
    local scenario=$1 config=$2 port=$3 prime_cache=${4:-false}

    log "STARTING ZION: $scenario (port $port)"
    cd "$PROJECT_DIR"
    ZION_CONFIG="$config" ./target/release/zion 2>/dev/null &
    ZION_PID=$!
    wait_for_https "https://127.0.0.1:${port}/"

    if [[ "$prime_cache" == "true" ]]; then
        curl -sk -H "Host: bench.local" "https://127.0.0.1:${port}/_next/static/chunk.js" >/dev/null
        log "  Cache primed"
    fi

    for ep in "${ENDPOINTS[@]}"; do
        IFS='|' read -r label path method body <<< "$ep"
        log "ZION $scenario: $label ($method $path)"
        run_hey "zion_${scenario}_${label}" "https://127.0.0.1:${port}${path}" "$method" "$body"
    done

    kill "$ZION_PID" 2>/dev/null; wait "$ZION_PID" 2>/dev/null || true; ZION_PID=""
    sleep 1
}

run_zion_scenario "tls"      "benchmarks/zion-bench-tls.toml"          4430 false
run_zion_scenario "waf"      "benchmarks/zion-bench-tls-waf.toml"      4431 false
run_zion_scenario "full"     "benchmarks/zion-bench-tls-waf-cache.toml" 4433 true

# ============================================================================
# EXPORT RESULTS AS JSON (for PDF generator)
# ============================================================================

log "EXPORTING RESULTS"

python3 - "$RESULTS_DIR" << 'PYEOF'
import sys, os, re, json

rdir = sys.argv[1]
results = {}

for fname in sorted(os.listdir(rdir)):
    if not fname.endswith("_best.txt"):
        continue
    name = fname.replace("_best.txt", "")
    path = os.path.join(rdir, fname)
    with open(path) as f:
        text = f.read()

    rps = float(re.search(r"Requests/sec:\s+([\d.]+)", text).group(1))
    avg = float(re.search(r"Average:\s+([\d.]+)", text).group(1)) * 1000

    pcts = {}
    for m in re.finditer(r"(\d+)%%\s+in\s+([\d.]+)\s+secs", text):
        pcts[f"p{m.group(1)}"] = round(float(m.group(2)) * 1000, 2)

    slowest = float(re.search(r"Slowest:\s+([\d.]+)", text).group(1)) * 1000

    results[name] = {
        "rps": round(rps, 1),
        "avg_ms": round(avg, 2),
        "p50_ms": pcts.get("p50", 0),
        "p95_ms": pcts.get("p95", 0),
        "p99_ms": pcts.get("p99", 0),
        "max_ms": round(slowest, 2),
    }

out = os.path.join(rdir, "results.json")
with open(out, "w") as f:
    json.dump(results, f, indent=2)
print(f"  Saved {len(results)} results to {out}")
PYEOF

log "DONE. Results in: $RESULTS_DIR"
echo "$RESULTS_DIR"
