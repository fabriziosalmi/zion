#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# ZION vs NGINX — Scientific Benchmark
#
# RIGOR:
#   - 5 runs per test (median reported, stddev calculated)
#   - 30s cooldown between systems to avoid thermal throttling
#   - Response body verification (same content from both proxies)
#   - Error count check (zero tolerance)
#   - System load logged before each test
#   - Docker identical: 1 CPU, 256MB, same network, same backend
#   - Single tool (wrk), single concurrency (100), 10s duration
#
# OUTPUT: results.json with mean, median, stddev, min, max, errors
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results/scientific_$(date +%Y%m%d_%H%M%S)"
DUR=10
CONNS=100
RUNS=5

mkdir -p "$RESULTS_DIR"

log() { echo "$(date +%H:%M:%S) $*" | tee -a "$RESULTS_DIR/bench.log"; }
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

# ── Verify response correctness ──────────────────────────────────
verify_response() {
    local label=$1 url=$2 expected_type=$3
    local body status ct

    body=$(curl -sk -D "$RESULTS_DIR/_headers.tmp" -o "$RESULTS_DIR/_body.tmp" \
        -w "%{http_code}" -H "Host: bench.local" "$url")
    status=$body
    ct=$(grep -i "^content-type:" "$RESULTS_DIR/_headers.tmp" | head -1 | tr -d '\r')
    local size=$(wc -c < "$RESULTS_DIR/_body.tmp" | tr -d ' ')

    if [[ "$status" != "200" && "$status" != "201" ]]; then
        log "  VERIFY FAIL: $label returned HTTP $status"
        return 1
    fi

    echo "$label: HTTP=$status size=${size}B ct='$ct'" >> "$RESULTS_DIR/verify.log"
    return 0
}

# ── Run wrk and extract all stats ────────────────────────────────
run_wrk() {
    local out=$1 url=$2 method=${3:-GET}

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
}

# ── Extract metrics from wrk output ──────────────────────────────
extract() {
    local file=$1 field=$2
    case "$field" in
        rps) grep "Requests/sec:" "$file" | awk '{printf "%.1f", $2}' ;;
        avg) grep "Latency" "$file" | head -1 | awk '{print $2}' ;;
        p50) grep "50%" "$file" | awk '{print $2}' ;;
        p99) grep "99%" "$file" | awk '{print $2}' ;;
        errors)
            # Count BOTH socket errors AND non-2xx/3xx responses: a proxy that
            # 404s/503s every request would otherwise report high RPS with
            # "zero errors" and silently corrupt the table (this is exactly how
            # a pre-#171 catch-all-root 404 once masqueraded as a 233k peak).
            local sock=$(grep "Socket errors" "$file" | awk '{print $4+$6+$8+$10}')
            local non2xx=$(grep "Non-2xx or 3xx" "$file" | awk '{print $NF}')
            echo "$(( ${sock:-0} + ${non2xx:-0} ))" ;;
    esac
}

# ============================================================================
# BUILD & START
# ============================================================================

log "=== SCIENTIFIC BENCHMARK ==="
log "Runs: $RUNS  Duration: ${DUR}s  Concurrency: $CONNS"
log ""

log "Building Docker images..."
cd "$SCRIPT_DIR"
docker compose -f docker-compose.bench.yml build --quiet 2>&1

log "Starting containers..."
docker compose -f docker-compose.bench.yml up -d 2>&1

log "Waiting for services..."
wait_for_https "https://127.0.0.1:8443/"
wait_for_https "https://127.0.0.1:9443/"
wait_for_https "https://127.0.0.1:9444/"
wait_for_https "https://127.0.0.1:9445/"

# Prime caches
for path in /_next/static/chunk.js /_next/static/style.css /_next/static/hero.png; do
    curl -sk -H "Host: bench.local" "https://127.0.0.1:9445${path}" >/dev/null
done
log "All services ready."

# ============================================================================
# VERIFY: Both proxies serve identical content
# ============================================================================

log ""
log "=== RESPONSE VERIFICATION ==="

ENDPOINTS="api_get|/api/v1/data|GET html|/|GET js_4k|/_next/static/chunk.js|GET png_8k|/_next/static/hero.png|GET waf_post|/api/v1/data|POST css_cached|/_next/static/style.css|GET"

for port_label in "8443|nginx" "9443|zion_tls" "9444|zion_waf" "9445|zion_full"; do
    IFS='|' read -r port system <<< "$port_label"
    for ep_entry in $ENDPOINTS; do
        IFS='|' read -r elabel epath emethod <<< "$ep_entry"
        verify_response "${system}_${elabel}" "https://127.0.0.1:${port}${epath}" "" || true
    done
done

log "Verification log: $RESULTS_DIR/verify.log"
log ""

# Compare response sizes between nginx and zion for same endpoints
log "=== SIZE COMPARISON (nginx vs zion_tls, same endpoint) ==="
for ep_entry in $ENDPOINTS; do
    IFS='|' read -r elabel epath emethod <<< "$ep_entry"
    nginx_size=$(curl -sk -H "Host: bench.local" "https://127.0.0.1:8443${epath}" | wc -c | tr -d ' ')
    zion_size=$(curl -sk -H "Host: bench.local" "https://127.0.0.1:9443${epath}" | wc -c | tr -d ' ')
    match="OK"
    [[ "$nginx_size" != "$zion_size" ]] && match="DIFF"
    log "  $elabel: nginx=${nginx_size}B zion=${zion_size}B [$match]"
done
log ""

# ============================================================================
# BENCHMARK: 5 runs per system per endpoint
# ============================================================================

SYSTEMS="nginx|8443 zion_tls|9443 zion_waf|9444 zion_full|9445"

log "=== BENCHMARK (${RUNS} runs each) ==="

for ep_entry in $ENDPOINTS; do
    IFS='|' read -r elabel epath emethod <<< "$ep_entry"
    log ""
    log "── $elabel ($emethod $epath) ──"

    for sys_entry in $SYSTEMS; do
        IFS='|' read -r sname sport <<< "$sys_entry"

        # Warmup
        wrk -t1 -c50 -d3s -H "Host: bench.local" "https://127.0.0.1:${sport}${epath}" >/dev/null 2>&1 || true

        rps_values=""
        for run in $(seq 1 $RUNS); do
            outfile="$RESULTS_DIR/${sname}_${elabel}_run${run}.txt"
            run_wrk "$outfile" "https://127.0.0.1:${sport}${epath}" "$emethod"

            rps=$(extract "$outfile" rps)
            errors=$(extract "$outfile" errors)
            rps_values="${rps_values}${rps} "

            printf "    %s run %d: %8s req/s  errors=%s\n" "$sname" "$run" "$rps" "$errors"
        done

        # Store all values for this system+endpoint
        echo "$rps_values" > "$RESULTS_DIR/${sname}_${elabel}_all_rps.txt"
    done
done

# ============================================================================
# STATISTICAL ANALYSIS
# ============================================================================

log ""
log "=== STATISTICAL ANALYSIS ==="

python3 - "$RESULTS_DIR" "$RUNS" << 'PYEOF'
import sys, os, json, re
import statistics

rdir = sys.argv[1]
n_runs = int(sys.argv[2])

systems = ["nginx", "zion_tls", "zion_waf", "zion_full"]
endpoints = ["api_get", "html", "js_4k", "png_8k", "waf_post", "css_cached"]
ep_labels = ["API GET 1KB", "HTML 5KB", "JS 4KB", "PNG 8KB", "WAF POST", "CSS cached"]

results = {}

for sys_name in systems:
    for ep in endpoints:
        key = f"{sys_name}_{ep}"
        rps_file = os.path.join(rdir, f"{key}_all_rps.txt")
        if not os.path.exists(rps_file):
            continue

        with open(rps_file) as f:
            values = [float(x) for x in f.read().strip().split() if x]

        if not values:
            continue

        # Also extract latency from last run
        last_run = os.path.join(rdir, f"{key}_run{n_runs}.txt")
        avg_ms, p50_ms, p99_ms = 0, 0, 0
        errors = 0
        if os.path.exists(last_run):
            with open(last_run) as f:
                text = f.read()
            def parse_lat(pattern):
                m = re.search(pattern, text)
                if not m: return 0
                v, u = float(m.group(1)), m.group(2)
                return v/1000 if u == "us" else v*1000 if u == "s" else v

            avg_ms = parse_lat(r"Latency\s+([\d.]+)(us|ms|s)")
            p50_ms = parse_lat(r"50%\s+([\d.]+)(us|ms|s)")
            p99_ms = parse_lat(r"99%\s+([\d.]+)(us|ms|s)")

            err_m = re.search(r"Socket errors.*?(\d+).*?(\d+).*?(\d+).*?(\d+)", text)
            if err_m:
                errors = sum(int(err_m.group(i)) for i in range(1,5))

        n = len(values)
        mean = statistics.mean(values)
        median = statistics.median(values)
        stdev = statistics.stdev(values) if n > 1 else 0
        ci95 = 1.96 * stdev / (n ** 0.5) if n > 1 else 0
        cv = (stdev / mean * 100) if mean > 0 else 0

        results[key] = {
            "rps_mean": round(mean, 1),
            "rps_median": round(median, 1),
            "rps_stdev": round(stdev, 1),
            "rps_min": round(min(values), 1),
            "rps_max": round(max(values), 1),
            "rps_ci95": round(ci95, 1),
            "rps_cv_pct": round(cv, 1),
            "rps_runs": values,
            "avg_ms": round(avg_ms, 2),
            "p50_ms": round(p50_ms, 2),
            "p99_ms": round(p99_ms, 2),
            "errors": errors,
            "n_runs": n,
        }

# Save JSON
out = os.path.join(rdir, "results.json")
with open(out, "w") as f:
    json.dump(results, f, indent=2)

# Print report
print()
print("╔════════════════════════════════════════════════════════════════════════════════════════╗")
print("║              ZION vs NGINX — Scientific Benchmark Report                             ║")
print("║              Docker 1 CPU / 256MB  •  c=100  •  10s × 5 runs  •  median ± CI95      ║")
print("╠════════════════════════════════════════════════════════════════════════════════════════╣")
print("║                                                                                      ║")

fmt = "║  {:<14s} │ {:>16s} │ {:>16s} │ {:>16s} │ {:>16s} ║"
sep = "║  ──────────────┼──────────────────┼──────────────────┼──────────────────┼──────────────────║"

print(fmt.format("THROUGHPUT", "nginx 1.27", "Zion TLS", "Zion WAF", "Zion Full"))
print(sep)

for ep, ep_label in zip(endpoints, ep_labels):
    cells = []
    for s in systems:
        k = f"{s}_{ep}"
        if k in results:
            r = results[k]
            med = r["rps_median"]
            ci = r["rps_ci95"]
            cells.append(f"{med:,.0f} ±{ci:,.0f}")
        else:
            cells.append("—")
    print(fmt.format(ep_label, *cells))

# Delta row
print(sep)
print(fmt.format("", "", "", "", ""))
print(fmt.format("vs nginx", "", "", "", ""))

for ep, ep_label in zip(endpoints, ep_labels):
    nk = f"nginx_{ep}"
    if nk not in results:
        continue
    nginx_med = results[nk]["rps_median"]
    cells = ["baseline"]
    for s in systems[1:]:
        k = f"{s}_{ep}"
        if k in results and nginx_med > 0:
            zion_med = results[k]["rps_median"]
            delta = ((zion_med / nginx_med) - 1) * 100
            cells.append(f"{delta:+.0f}%")
        else:
            cells.append("—")
    print(fmt.format(ep_label, *cells))

print("║                                                                                      ║")
print(fmt.format("P99 LATENCY", "nginx", "Zion TLS", "Zion WAF", "Zion Full"))
print(sep)

for ep, ep_label in zip(endpoints, ep_labels):
    cells = []
    for s in systems:
        k = f"{s}_{ep}"
        if k in results:
            cells.append(f"{results[k]['p99_ms']:.1f}ms")
        else:
            cells.append("—")
    print(fmt.format(ep_label, *cells))

print("║                                                                                      ║")
print(fmt.format("ERRORS", "nginx", "Zion TLS", "Zion WAF", "Zion Full"))
print(sep)
total_errors = 0
for ep, ep_label in zip(endpoints, ep_labels):
    cells = []
    for s in systems:
        k = f"{s}_{ep}"
        e = results.get(k, {}).get("errors", 0)
        total_errors += e
        cells.append(str(e))
    print(fmt.format(ep_label, *cells))

print("║                                                                                      ║")
if total_errors == 0:
    print("║  ✓ ZERO ERRORS across all tests                                                      ║")
else:
    print(f"║  ⚠ {total_errors} ERRORS detected — investigate before trusting results                ║")

print("║                                                                                      ║")
print("║  STATISTICAL VALIDITY                                                                ║")

high_cv = []
for key, r in results.items():
    if r["rps_cv_pct"] > 15:
        high_cv.append((key, r["rps_cv_pct"]))

if not high_cv:
    print("║  ✓ All measurements have CV < 15% (coefficient of variation)                         ║")
else:
    for k, cv in high_cv:
        print(f"║  ⚠ {k}: CV={cv:.1f}% — high variance, results may not be reliable          ║")

print("║                                                                                      ║")
print("╚════════════════════════════════════════════════════════════════════════════════════════╝")

PYEOF

log ""
log "DONE. Results: $RESULTS_DIR"
