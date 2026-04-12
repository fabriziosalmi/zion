#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# ZION PROFILING BENCHMARK (~3 min)
# Component overhead analysis via throughput delta.
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results/profile_$(date +%Y%m%d_%H%M%S)"
BACKEND_PID=""
ZION_PID=""
DUR=8
CONNS=200

mkdir -p "$RESULTS_DIR"

log() { echo -e "\n$(date +%H:%M:%S) >>> $*"; }
die() { echo "FATAL: $*" >&2; cleanup; exit 1; }
cleanup() {
    [[ -n "$ZION_PID" ]] && kill "$ZION_PID" 2>/dev/null || true
    [[ -n "$BACKEND_PID" ]] && kill "$BACKEND_PID" 2>/dev/null || true
}
trap cleanup EXIT

wait_for() { for _ in $(seq 1 15); do curl -sk --max-time 1 "$1" >/dev/null 2>&1 && return 0; sleep 0.5; done; die "Timeout: $1"; }

# Run wrk, print "rps|avg|p50|p99"
run_wrk() {
    local label=$1 url=$2 method=${3:-GET}
    local out="$RESULTS_DIR/wrk_${label}.txt"
    if [[ "$method" == "POST" ]]; then
        cat > "$RESULTS_DIR/_post.lua" << 'LUA'
wrk.method = "POST"
wrk.headers["Content-Type"] = "application/json"
wrk.headers["Host"] = "bench.local"
wrk.body = '{"username":"testuser","email":"test@example.com","data":{"nested":true,"items":[1,2,3,4,5]}}'
LUA
        wrk -t4 -c"$CONNS" -d"${DUR}s" -s "$RESULTS_DIR/_post.lua" --latency "$url" > "$out" 2>&1
    else
        wrk -t4 -c"$CONNS" -d"${DUR}s" -H "Host: bench.local" --latency "$url" > "$out" 2>&1
    fi
    grep "Requests/sec:" "$out" | awk '{printf "%.0f", $2}'
}

run_wrk_c() {
    local c=$1 url=$2
    local out="$RESULTS_DIR/wrk_conc_c${c}.txt"
    local t=$((c < 4 ? 1 : (c < 100 ? 2 : 4)))
    wrk -t"$t" -c"$c" -d"${DUR}s" -H "Host: bench.local" --latency "$url" > "$out" 2>&1
    local rps avg p99
    rps=$(grep "Requests/sec:" "$out" | awk '{printf "%.0f", $2}')
    avg=$(grep "Latency" "$out" | head -1 | awk '{print $2}')
    p99=$(grep "99%" "$out" | awk '{print $2}')
    echo "${rps:-0}|${avg:-?}|${p99:-?}"
}

mem() {
    local label=$1
    local rss=$(ps -o rss= -p "$ZION_PID" 2>/dev/null | awk '{printf "%.1f", $1/1024}')
    echo "$label: ${rss:-?}MB" | tee -a "$RESULTS_DIR/memory.txt"
}

start_zion() { cd "$PROJECT_DIR"; ZION_CONFIG="$1" ./target/release/zion 2>/dev/null & ZION_PID=$!; wait_for "https://127.0.0.1:${2}/"; }
stop_zion() { [[ -n "$ZION_PID" ]] && kill "$ZION_PID" 2>/dev/null && wait "$ZION_PID" 2>/dev/null || true; ZION_PID=""; sleep 0.3; }

# ============================================================================

log "BUILDING (release + debug symbols)"
cd "$PROJECT_DIR"
CARGO_PROFILE_RELEASE_STRIP="none" CARGO_PROFILE_RELEASE_DEBUG=2 \
    cargo build --release --quiet 2>&1

log "STARTING BACKEND"
cd "$SCRIPT_DIR/backend" && go run main.go 2>/dev/null &
BACKEND_PID=$!
sleep 1

# ── Phase 1: Baseline ────────────────────────────────────────────
log "PHASE 1: TLS + Routing baseline"
start_zion "benchmarks/zion-bench-tls.toml" 4430
wrk -t2 -c50 -d2s -H "Host: bench.local" "https://127.0.0.1:4430/api/v1/data" >/dev/null 2>&1

# CPU sample during load (background, no sudo needed on macOS)
sample "$ZION_PID" "$DUR" -f "$RESULTS_DIR/sample_tls.txt" 2>/dev/null &

TLS_API=$(run_wrk tls_api "https://127.0.0.1:4430/api/v1/data")
TLS_HTML=$(run_wrk tls_html "https://127.0.0.1:4430/")
TLS_STATIC=$(run_wrk tls_static "https://127.0.0.1:4430/_next/static/chunk.js")
mem "tls_loaded"
stop_zion

# ── Phase 2: WAF ─────────────────────────────────────────────────
log "PHASE 2: WAF overhead"
start_zion "benchmarks/zion-bench-tls-waf.toml" 4431
wrk -t2 -c50 -d2s -H "Host: bench.local" "https://127.0.0.1:4431/api/v1/data" >/dev/null 2>&1

sample "$ZION_PID" "$DUR" -f "$RESULTS_DIR/sample_waf.txt" 2>/dev/null &

WAF_GET=$(run_wrk waf_get "https://127.0.0.1:4431/api/v1/data")
WAF_POST=$(run_wrk waf_post "https://127.0.0.1:4431/api/v1/data" POST)
mem "waf_post"
stop_zion

# ── Phase 3: Cache ───────────────────────────────────────────────
log "PHASE 3: Cache miss vs hit"
start_zion "benchmarks/zion-bench-tls-cache.toml" 4432
wrk -t2 -c50 -d2s -H "Host: bench.local" "https://127.0.0.1:4432/_next/static/chunk.js" >/dev/null 2>&1

CACHE_MISS=$(run_wrk cache_miss "https://127.0.0.1:4432/_next/static/chunk.js")

curl -sk -H "Host: bench.local" "https://127.0.0.1:4432/_next/static/chunk.js" >/dev/null

sample "$ZION_PID" "$DUR" -f "$RESULTS_DIR/sample_cache.txt" 2>/dev/null &

CACHE_HIT=$(run_wrk cache_hit "https://127.0.0.1:4432/_next/static/chunk.js")
mem "cache_hit"
stop_zion

# ── Phase 4: Concurrency scaling ─────────────────────────────────
log "PHASE 4: Concurrency scaling"
start_zion "benchmarks/zion-bench-tls.toml" 4430
wrk -t2 -c50 -d2s -H "Host: bench.local" "https://127.0.0.1:4430/api/v1/data" >/dev/null 2>&1

CONC_DATA=""
for c in 1 10 50 200 500 1000; do
    result=$(run_wrk_c "$c" "https://127.0.0.1:4430/api/v1/data")
    CONC_DATA="${CONC_DATA}${c}|${result}\n"
done
mem "conc_1000"
stop_zion

# ── Phase 5: Response size ───────────────────────────────────────
log "PHASE 5: Response size impact"
start_zion "benchmarks/zion-bench-tls.toml" 4430

SIZE_SMALL=$(run_wrk size_small "https://127.0.0.1:4430/")
SIZE_1K=$(run_wrk size_1kb "https://127.0.0.1:4430/api/v1/data")
SIZE_4K=$(run_wrk size_4kb "https://127.0.0.1:4430/_next/static/chunk.js")
SIZE_100K=$(run_wrk size_100kb "https://127.0.0.1:4430/api/v1/large?size=102400")
stop_zion

# ============================================================================
# REPORT
# ============================================================================

# Overhead calculations
WAF_GET_OH=$(echo "scale=1; (1 - $WAF_GET / $TLS_API) * 100" | bc)
WAF_POST_OH=$(echo "scale=1; (1 - $WAF_POST / $TLS_API) * 100" | bc)
BODY_OH=$(echo "scale=1; (1 - $WAF_POST / $WAF_GET) * 100" | bc)
CACHE_UP=$(echo "scale=0; ($CACHE_HIT * 100 / $CACHE_MISS) - 100" | bc)

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║              ZION PROFILING REPORT — $(date +%Y-%m-%d)                  ║"
echo "║              Commit: $(cd "$PROJECT_DIR" && git rev-parse --short HEAD)  •  c=$CONNS  •  ${DUR}s/test              ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║                                                                ║"
echo "║  COMPONENT OVERHEAD                                            ║"
echo "║  ────────────────────────────────────────────────────────────── ║"
printf "║  %-35s %8s %9s  ║\n" "" "Req/s" "Overhead"
printf "║  %-35s %8s %9s  ║\n" "───────────────────────────────────" "────────" "─────────"
printf "║  %-35s %8s %9s  ║\n" "TLS 1.3 + Radix routing" "$TLS_API" "baseline"
printf "║  %-35s %8s %8s%%  ║\n" "+ WAF check (GET, no body)" "$WAF_GET" "$WAF_GET_OH"
printf "║  %-35s %8s %8s%%  ║\n" "+ WAF + body collect + JSON parse" "$WAF_POST" "$WAF_POST_OH"
printf "║    %-33s %8s %8s%%  ║\n" "└─ body parse cost alone" "" "$BODY_OH"
printf "║  %-35s %8s %9s  ║\n" "Cache MISS (upstream roundtrip)" "$CACHE_MISS" ""
printf "║  %-35s %8s %7s%%   ║\n" "Cache HIT (DashMap zero-copy)" "$CACHE_HIT" "+$CACHE_UP"
echo "║                                                                ║"
echo "║  CONCURRENCY SCALING (API GET)                                 ║"
echo "║  ────────────────────────────────────────────────────────────── ║"
printf "║  %-12s %8s %10s %10s               ║\n" "Clients" "Req/s" "Avg Lat" "P99 Lat"
printf "║  %-12s %8s %10s %10s               ║\n" "────────────" "────────" "──────────" "──────────"
echo -e "$CONC_DATA" | while IFS='|' read -r c rps avg p99; do
    [[ -z "$c" ]] && continue
    printf "║  c=%-9s %8s %10s %10s               ║\n" "$c" "$rps" "$avg" "$p99"
done
echo "║                                                                ║"
echo "║  RESPONSE SIZE IMPACT (TLS, c=$CONNS)                          ║"
echo "║  ────────────────────────────────────────────────────────────── ║"
printf "║  %-20s %8s                                  ║\n" "~30B (HTML)" "$SIZE_SMALL"
printf "║  %-20s %8s                                  ║\n" "~1KB (JSON API)" "$SIZE_1K"
printf "║  %-20s %8s                                  ║\n" "~4KB (JS chunk)" "$SIZE_4K"
printf "║  %-20s %8s                                  ║\n" "100KB (binary)" "$SIZE_100K"
echo "║                                                                ║"
echo "║  MEMORY (RSS)                                                  ║"
echo "║  ────────────────────────────────────────────────────────────── ║"
while IFS= read -r line; do
    printf "║    %-60s ║\n" "$line"
done < "$RESULTS_DIR/memory.txt"
echo "║                                                                ║"

# Identify biggest bottleneck
echo "║  DIAGNOSIS                                                     ║"
echo "║  ────────────────────────────────────────────────────────────── ║"
if (( $(echo "$WAF_POST_OH > 20" | bc -l) )); then
    printf "║    ⚠ WAF POST overhead is %.0f%% — body collection +          ║\n" "$WAF_POST_OH"
    echo "║      serde_json::from_slice is the main cost.                 ║"
    echo "║      Optimize: lazy parsing, simd-json, or skip for           ║"
    echo "║      trusted internal routes.                                  ║"
elif (( $(echo "$WAF_GET_OH > 10" | bc -l) )); then
    printf "║    ⚠ WAF GET overhead is %.0f%% — content-type check          ║\n" "$WAF_GET_OH"
    echo "║      and method matching have measurable cost.                 ║"
fi
if (( $(echo "$CACHE_UP < 20" | bc -l) )); then
    echo "║    ⚠ Cache speedup is only +${CACHE_UP}% — TLS handshake       ║"
    echo "║      dominates. Cache benefits more at higher concurrency.     ║"
fi

echo "║    Run 'open \$RESULTS_DIR/sample_tls.txt' for CPU stacks.     ║"

echo "║                                                                ║"
echo "╚══════════════════════════════════════════════════════════════════╝"

# Save JSON
cat > "$RESULTS_DIR/profile.json" << JSONEOF
{
    "commit": "$(cd "$PROJECT_DIR" && git rev-parse --short HEAD)",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "tls_api_rps": $TLS_API, "tls_html_rps": $TLS_HTML, "tls_static_rps": $TLS_STATIC,
    "waf_get_rps": $WAF_GET, "waf_post_rps": $WAF_POST,
    "waf_get_overhead_pct": $WAF_GET_OH, "waf_post_overhead_pct": $WAF_POST_OH,
    "body_parse_overhead_pct": $BODY_OH,
    "cache_miss_rps": $CACHE_MISS, "cache_hit_rps": $CACHE_HIT,
    "cache_speedup_pct": $CACHE_UP,
    "size_small_rps": $SIZE_SMALL, "size_1kb_rps": $SIZE_1K,
    "size_4kb_rps": $SIZE_4K, "size_100kb_rps": $SIZE_100K
}
JSONEOF

log "Profile data: $RESULTS_DIR/profile.json"
[[ -f "$RESULTS_DIR/sample_tls.txt" ]] && log "CPU sample: $RESULTS_DIR/sample_tls.txt"
