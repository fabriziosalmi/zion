#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# ZION vs NGINX — Fair Docker Benchmark
#
# IDENTICAL CONDITIONS:
#   Both proxies: Docker, 1 CPU, 256MB RAM, same network, same backend
#   Backend: Go test-server, Docker, 2 CPU, 512MB
#   Tool: wrk (single tool, reproducible)
#   Duration: 10s per test, 1 warmup
#   Concurrency: 100 (typical production)
#
# ENDPOINTS: 6 (matching smoke suite categories)
#   API GET (1KB JSON), HTML (5KB), JS (4KB), PNG (8KB)
#   WAF POST (JSON body), Cache hit (4KB JS from RAM)
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results/fair_$(date +%Y%m%d_%H%M%S)"
DUR=10
CONNS=100
NGINX_CONTAINER="zion-bench-nginx"

mkdir -p "$RESULTS_DIR"

log() { echo "$(date +%H:%M:%S) $*"; }
die() { echo "FATAL: $*" >&2; cleanup; exit 1; }

cleanup() {
    cd "$SCRIPT_DIR"
    docker compose -f docker-compose.bench.yml down 2>/dev/null || true
}
trap cleanup EXIT

wait_for_https() {
    for _ in $(seq 1 60); do curl -sk --max-time 2 "$1" >/dev/null 2>&1 && return 0; sleep 1; done
    die "Timeout: $1"
}

# Run wrk, extract rps + avg latency + p99
bench() {
    local label=$1 url=$2 method=${3:-GET}
    local out="$RESULTS_DIR/${label}.txt"

    if [[ "$method" == "POST" ]]; then
        cat > "$RESULTS_DIR/_post.lua" << 'LUA'
wrk.method = "POST"
wrk.headers["Content-Type"] = "application/json"
wrk.headers["Host"] = "bench.local"
wrk.body = '{"username":"test","email":"t@t.com","data":{"n":true}}'
LUA
        wrk -t2 -c"$CONNS" -d"${DUR}s" -s "$RESULTS_DIR/_post.lua" --latency "$url" > "$out" 2>&1
    else
        wrk -t2 -c"$CONNS" -d"${DUR}s" -H "Host: bench.local" --latency "$url" > "$out" 2>&1
    fi

    local rps avg p99
    rps=$(grep "Requests/sec:" "$out" | awk '{printf "%.0f", $2}')
    # Extract avg latency from wrk format: "Latency   1.23ms  ..."
    avg=$(grep "Latency" "$out" | head -1 | awk '{print $2}')
    p99=$(grep "99%" "$out" | awk '{print $2}')
    echo "${rps:-0}|${avg:-?}|${p99:-?}"
}

# ============================================================================
# BUILD & START
# ============================================================================

log "Building Docker images..."
cd "$SCRIPT_DIR"
docker compose -f docker-compose.bench.yml build --quiet 2>&1

log "Starting containers..."
docker compose -f docker-compose.bench.yml up -d 2>&1

log "Waiting for services..."
wait_for_https "https://127.0.0.1:8443/"  # nginx
wait_for_https "https://127.0.0.1:9443/"  # zion-tls
wait_for_https "https://127.0.0.1:9444/"  # zion-waf
wait_for_https "https://127.0.0.1:9445/"  # zion-full

# Prime caches
curl -sk -H "Host: bench.local" "https://127.0.0.1:9445/_next/static/chunk.js" >/dev/null
curl -sk -H "Host: bench.local" "https://127.0.0.1:9445/_next/static/style.css" >/dev/null
curl -sk -H "Host: bench.local" "https://127.0.0.1:9445/_next/static/hero.png" >/dev/null

# Warmup all targets
for port in 8443 9443 9444 9445; do
    wrk -t1 -c50 -d3s -H "Host: bench.local" "https://127.0.0.1:${port}/api/v1/data" >/dev/null 2>&1 || true
done
log "All ready."

echo ""
echo "┌──────────────────────────────────────────────────────────────┐"
echo "│ FAIR TEST: Docker, 1 CPU, 256MB per proxy, same backend     │"
echo "│ Duration: ${DUR}s  Concurrency: ${CONNS}  Tool: wrk                  │"
echo "└──────────────────────────────────────────────────────────────┘"
echo ""

# ============================================================================
# RUN ALL BENCHMARKS
# ============================================================================

# Targets: system|port
TARGETS="nginx|8443 zion_tls|9443 zion_waf|9444 zion_full|9445"

# Endpoints: label|path|method
ENDPOINTS="api_get|/api/v1/data|GET html|/|GET js_4k|/_next/static/chunk.js|GET png_8k|/_next/static/hero.png|GET waf_post|/api/v1/data|POST css_cached|/_next/static/style.css|GET"

for ep_entry in $ENDPOINTS; do
    IFS='|' read -r elabel epath emethod <<< "$ep_entry"
    log "Benchmarking: $elabel ($emethod $epath)"

    for target_entry in $TARGETS; do
        IFS='|' read -r tname tport <<< "$target_entry"
        result=$(bench "${tname}_${elabel}" "https://127.0.0.1:${tport}${epath}" "$emethod")
        IFS='|' read -r rps avg p99 <<< "$result"
        printf "  %-12s %8s req/s  avg=%s  p99=%s\n" "$tname" "$rps" "$avg" "$p99"
    done
    echo ""
done

# ============================================================================
# GENERATE REPORT
# ============================================================================

log "Generating report..."

echo ""
echo "╔══════════════════════════════════════════════════════════════════════════════════╗"
echo "║          ZION vs NGINX — Fair Docker Benchmark Report                          ║"
echo "║          $(date +%Y-%m-%d)  •  Docker 1 CPU / 256MB  •  c=${CONNS}  •  ${DUR}s/test              ║"
echo "╠══════════════════════════════════════════════════════════════════════════════════╣"
echo "║                                                                                ║"

printf "║  %-14s │ %10s │ %10s │ %10s │ %10s │ %7s ║\n" "Endpoint" "nginx" "Zion TLS" "Zion WAF" "Zion Full" "vs nginx"
echo "║  ──────────────┼────────────┼────────────┼────────────┼────────────┼──────── ║"

for ep_entry in $ENDPOINTS; do
    IFS='|' read -r elabel epath emethod <<< "$ep_entry"

    nginx_rps=0; ztls_rps=0; zwaf_rps=0; zfull_rps=0

    for target_entry in $TARGETS; do
        IFS='|' read -r tname tport <<< "$target_entry"
        f="$RESULTS_DIR/${tname}_${elabel}.txt"
        rps=$(grep "Requests/sec:" "$f" 2>/dev/null | awk '{printf "%.0f", $2}')
        rps=${rps:-0}

        case "$tname" in
            nginx)    nginx_rps=$rps ;;
            zion_tls) ztls_rps=$rps ;;
            zion_waf) zwaf_rps=$rps ;;
            zion_full) zfull_rps=$rps ;;
        esac
    done

    # Best Zion vs nginx
    best=$ztls_rps
    [[ $zwaf_rps -gt $best ]] && best=$zwaf_rps
    [[ $zfull_rps -gt $best ]] && best=$zfull_rps
    if [[ $nginx_rps -gt 0 ]]; then
        delta=$(echo "scale=0; ($best * 100 / $nginx_rps) - 100" | bc)
        delta_str="+${delta}%"
        [[ $delta -lt 0 ]] && delta_str="${delta}%"
    else
        delta_str="n/a"
    fi

    printf "║  %-14s │ %'10d │ %'10d │ %'10d │ %'10d │ %7s ║\n" \
        "$elabel" "$nginx_rps" "$ztls_rps" "$zwaf_rps" "$zfull_rps" "$delta_str"
done

echo "║                                                                                ║"
echo "║  LATENCY (P99)                                                                 ║"
printf "║  %-14s │ %10s │ %10s │ %10s │ %10s │         ║\n" "Endpoint" "nginx" "Zion TLS" "Zion WAF" "Zion Full"
echo "║  ──────────────┼────────────┼────────────┼────────────┼────────────┼──────── ║"

for ep_entry in $ENDPOINTS; do
    IFS='|' read -r elabel epath emethod <<< "$ep_entry"
    vals=()
    for target_entry in $TARGETS; do
        IFS='|' read -r tname tport <<< "$target_entry"
        f="$RESULTS_DIR/${tname}_${elabel}.txt"
        p99=$(grep "99%" "$f" 2>/dev/null | awk '{print $2}')
        vals+=("${p99:-?}")
    done
    printf "║  %-14s │ %10s │ %10s │ %10s │ %10s │         ║\n" \
        "$elabel" "${vals[0]}" "${vals[1]}" "${vals[2]}" "${vals[3]}"
done

echo "║                                                                                ║"
echo "║  CONDITIONS                                                                    ║"
echo "║    nginx: 1.27-alpine, 1 worker, access_log off, keepalive 64                  ║"
echo "║    Zion TLS: proxy only (apples-to-apples with nginx)                          ║"
echo "║    Zion WAF: TLS + Aho-Corasick scanner + entropy + simd-json                  ║"
echo "║    Zion Full: TLS + WAF + DashMap RAM cache                                    ║"
echo "║    Backend: Go test-server (2 CPU, 512MB, Docker)                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════════╝"

# Save JSON
python3 - "$RESULTS_DIR" << 'PYEOF'
import sys, os, re, json

rdir = sys.argv[1]
results = {}

for fname in sorted(os.listdir(rdir)):
    if not fname.endswith(".txt") or fname.startswith("_"):
        continue
    fpath = os.path.join(rdir, fname)
    key = fname.replace(".txt", "")
    with open(fpath) as f:
        text = f.read()

    rps_m = re.search(r"Requests/sec:\s+([\d.]+)", text)
    if not rps_m:
        continue

    avg_m = re.search(r"Latency\s+([\d.]+)(us|ms|s)", text)
    p99_m = re.search(r"99%\s+([\d.]+)(us|ms|s)", text)

    def to_ms(m):
        if not m: return 0
        v, u = float(m.group(1)), m.group(2)
        return v/1000 if u == "us" else v*1000 if u == "s" else v

    results[key] = {
        "rps": round(float(rps_m.group(1)), 1),
        "avg_ms": round(to_ms(avg_m), 2),
        "p99_ms": round(to_ms(p99_m), 2),
    }

out = os.path.join(rdir, "results.json")
with open(out, "w") as f:
    json.dump(results, f, indent=2)
print(f"  {len(results)} results → {out}")
PYEOF

# Generate PDF
python3 "$SCRIPT_DIR/generate-report.py" "$RESULTS_DIR" 2>&1

log "DONE. Results: $RESULTS_DIR"
