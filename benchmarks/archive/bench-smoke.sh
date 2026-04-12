#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# ZION SMOKE BENCHMARK — 10 metrics, ~2 minutes
#
# Categories:
#   PERF:  TLS proxy, HTML, cache hit, WAF POST
#   STATIC: JS, CSS, PNG, font
#   SEC:   SQLi blocked, XSS blocked
#
# Architectures (--arch flag):
#   native     — local build, local backend (default)
#   docker-arm — Docker arm64 containers
#   docker-amd — Docker amd64 containers
#   remote     — SSH to Linux LXC (192.168.100.59)
#
# Exit codes: 0=pass, 1=regression (>15%), 2=infra error
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
HISTORY_FILE="$SCRIPT_DIR/bench-history.json"
BACKEND_PID=""
ZION_PID=""
REGRESSION_THRESHOLD=15
DURATION=5
CONNECTIONS=100
ARCH="native"

# Parse --arch flag
while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch) ARCH="$2"; shift 2 ;;
        *) shift ;;
    esac
done

log() { echo "$(date +%H:%M:%S) $*"; }
die() { echo "FATAL: $*" >&2; cleanup; exit 2; }

cleanup() {
    [[ -n "$ZION_PID" ]] && kill "$ZION_PID" 2>/dev/null || true
    [[ -n "$BACKEND_PID" ]] && kill "$BACKEND_PID" 2>/dev/null || true
}
trap cleanup EXIT

wait_for_port() {
    for _ in $(seq 1 15); do nc -z "$1" "$2" 2>/dev/null && return 0; sleep 0.5; done
    die "Timeout: $1:$2"
}

wait_for_https() {
    for _ in $(seq 1 15); do curl -sk --max-time 2 "$1" >/dev/null 2>&1 && return 0; sleep 0.5; done
    die "Timeout: $1"
}

wrk_rps() {
    local url=$1 method=${2:-GET}
    local out
    out=$(mktemp)

    if [[ "$method" == "POST" ]]; then
        local lua
        lua=$(mktemp)
        cat > "$lua" << 'LUA'
wrk.method = "POST"
wrk.headers["Content-Type"] = "application/json"
wrk.headers["Host"] = "bench.local"
wrk.body = '{"username":"test","email":"t@t.com","data":{"n":true}}'
LUA
        wrk -t2 -c"$CONNECTIONS" -d"${DURATION}s" -s "$lua" "$url" > "$out" 2>&1
        rm -f "$lua"
    elif [[ "$method" == "POST_SQLI" ]]; then
        local lua
        lua=$(mktemp)
        cat > "$lua" << 'LUA'
wrk.method = "POST"
wrk.headers["Content-Type"] = "application/json"
wrk.headers["Host"] = "bench.local"
wrk.body = '{"user":"admin\' OR \'1\'=\'1","pass":"x"}'
LUA
        wrk -t1 -c10 -d"3s" -s "$lua" "$url" > "$out" 2>&1
        rm -f "$lua"
    elif [[ "$method" == "POST_XSS" ]]; then
        local lua
        lua=$(mktemp)
        cat > "$lua" << 'LUA'
wrk.method = "POST"
wrk.headers["Content-Type"] = "application/json"
wrk.headers["Host"] = "bench.local"
wrk.body = '{"name":"<script>alert(1)</script>"}'
LUA
        wrk -t1 -c10 -d"3s" -s "$lua" "$url" > "$out" 2>&1
        rm -f "$lua"
    else
        wrk -t2 -c"$CONNECTIONS" -d"${DURATION}s" -H "Host: bench.local" "$url" > "$out" 2>&1
    fi

    local rps
    rps=$(grep "Requests/sec:" "$out" | awk '{printf "%.0f", $2}')
    rm -f "$out"
    echo "${rps:-0}"
}

# Check WAF blocks (returns HTTP status code)
check_waf() {
    local url=$1 body=$2
    curl -sk -o /dev/null -w "%{http_code}" -X POST \
        -H "Host: bench.local" -H "Content-Type: application/json" \
        -d "$body" "$url"
}

# ============================================================================
# SETUP
# ============================================================================

log "Arch: $ARCH"
log "Building release..."
cd "$PROJECT_DIR"
cargo build --release 2>&1 | tail -1

log "Starting backend..."
cd "$SCRIPT_DIR/backend"
go run test-server.go 2>/dev/null &
BACKEND_PID=$!
wait_for_port 127.0.0.1 9090

# ============================================================================
# PERF: TLS proxy (API GET, 1KB JSON)
# ============================================================================

log "Test 1/10: TLS proxy (API GET)..."
cd "$PROJECT_DIR"
ZION_CONFIG=benchmarks/zion-bench-tls.toml ./target/release/zion 2>/dev/null &
ZION_PID=$!
wait_for_https "https://127.0.0.1:4430/"

TLS_RPS=$(wrk_rps "https://127.0.0.1:4430/api/v1/data")
log "  TLS proxy: $TLS_RPS req/s"

# ============================================================================
# PERF: HTML pass-through (5KB SSR page)
# ============================================================================

log "Test 2/10: HTML (5KB SSR)..."
HTML_RPS=$(wrk_rps "https://127.0.0.1:4430/")
log "  HTML:      $HTML_RPS req/s"

# ============================================================================
# STATIC: JS (4KB, via upstream — no cache on this config)
# ============================================================================

log "Test 3/10: Static JS (4KB)..."
JS_RPS=$(wrk_rps "https://127.0.0.1:4430/_next/static/chunk.js")
log "  JS:        $JS_RPS req/s"

# ============================================================================
# STATIC: PNG (8KB binary, via upstream)
# ============================================================================

log "Test 4/10: Static PNG (8KB)..."
PNG_RPS=$(wrk_rps "https://127.0.0.1:4430/_next/static/hero.png")
log "  PNG:       $PNG_RPS req/s"

kill "$ZION_PID" 2>/dev/null; wait "$ZION_PID" 2>/dev/null || true; ZION_PID=""
sleep 0.5

# ============================================================================
# PERF: WAF POST (JSON body, Aho-Corasick + simd-json + entropy)
# ============================================================================

log "Test 5/10: WAF POST (valid JSON)..."
ZION_CONFIG=benchmarks/zion-bench-tls-waf.toml ./target/release/zion 2>/dev/null &
ZION_PID=$!
wait_for_https "https://127.0.0.1:4431/"

WAF_RPS=$(wrk_rps "https://127.0.0.1:4431/api/v1/data" POST)
log "  WAF POST:  $WAF_RPS req/s"

# ============================================================================
# SEC: SQLi injection blocked
# ============================================================================

log "Test 6/10: WAF blocks SQLi..."
SQLI_CODE=$(check_waf "https://127.0.0.1:4431/api/v1/users" '{"user":"admin'\'' OR '\''1'\''='\''1","pass":"x"}')
if [[ "$SQLI_CODE" == "400" ]]; then
    log "  SQLi:      BLOCKED (400)"
    SQLI_OK=1
else
    log "  SQLi:      FAILED (got $SQLI_CODE, expected 400)"
    SQLI_OK=0
fi

# ============================================================================
# SEC: XSS injection blocked
# ============================================================================

log "Test 7/10: WAF blocks XSS..."
XSS_CODE=$(check_waf "https://127.0.0.1:4431/api/v1/users" '{"name":"<script>alert(1)</script>"}')
if [[ "$XSS_CODE" == "400" ]]; then
    log "  XSS:       BLOCKED (400)"
    XSS_OK=1
else
    log "  XSS:       FAILED (got $XSS_CODE, expected 400)"
    XSS_OK=0
fi

kill "$ZION_PID" 2>/dev/null; wait "$ZION_PID" 2>/dev/null || true; ZION_PID=""
sleep 0.5

# ============================================================================
# PERF: Cache hit (JS 4KB from RAM)
# ============================================================================

log "Test 8/10: Cache hit (RAM)..."
ZION_CONFIG=benchmarks/zion-bench-tls-cache.toml ./target/release/zion 2>/dev/null &
ZION_PID=$!
wait_for_https "https://127.0.0.1:4432/"

# Prime cache
curl -sk -H "Host: bench.local" "https://127.0.0.1:4432/_next/static/chunk.js" >/dev/null

CACHE_RPS=$(wrk_rps "https://127.0.0.1:4432/_next/static/chunk.js")
log "  Cache:     $CACHE_RPS req/s"

# ============================================================================
# STATIC: Font WOFF2 (16KB binary, via cache)
# ============================================================================

log "Test 9/10: Font WOFF2 (16KB, cached)..."
curl -sk -H "Host: bench.local" "https://127.0.0.1:4432/_next/static/font.woff2" >/dev/null
FONT_RPS=$(wrk_rps "https://127.0.0.1:4432/_next/static/font.woff2")
log "  Font:      $FONT_RPS req/s"

# ============================================================================
# STATIC: CSS (3KB, cached)
# ============================================================================

log "Test 10/10: CSS (3KB, cached)..."
curl -sk -H "Host: bench.local" "https://127.0.0.1:4432/_next/static/style.css" >/dev/null
CSS_RPS=$(wrk_rps "https://127.0.0.1:4432/_next/static/style.css")
log "  CSS:       $CSS_RPS req/s"

kill "$ZION_PID" 2>/dev/null; wait "$ZION_PID" 2>/dev/null || true; ZION_PID=""

# ============================================================================
# RESULTS
# ============================================================================

COMMIT=$(cd "$PROJECT_DIR" && git rev-parse --short HEAD)
BRANCH=$(cd "$PROJECT_DIR" && git branch --show-current)
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

RESULT_JSON=$(cat << EOF
{
    "commit": "$COMMIT",
    "branch": "$BRANCH",
    "arch": "$ARCH",
    "timestamp": "$TIMESTAMP",
    "tls_proxy_rps": $TLS_RPS,
    "html_rps": $HTML_RPS,
    "js_rps": $JS_RPS,
    "png_rps": $PNG_RPS,
    "waf_post_rps": $WAF_RPS,
    "cache_hit_rps": $CACHE_RPS,
    "font_rps": $FONT_RPS,
    "css_rps": $CSS_RPS,
    "sqli_blocked": $SQLI_OK,
    "xss_blocked": $XSS_OK
}
EOF
)

SEC_STATUS="PASS"
[[ "$SQLI_OK" == "0" || "$XSS_OK" == "0" ]] && SEC_STATUS="FAIL"

echo ""
echo "┌────────────────────────────────────────────────────┐"
printf "│ SMOKE RESULTS  %-35s│\n" "($COMMIT on $BRANCH)"
printf "│ arch: %-44s│\n" "$ARCH"
echo "├────────────────────────────────────────────────────┤"
echo "│ PERFORMANCE                                        │"
printf "│   TLS proxy (1KB JSON):   %'8d req/s           │\n" "$TLS_RPS"
printf "│   HTML (5KB SSR):         %'8d req/s           │\n" "$HTML_RPS"
printf "│   WAF POST (JSON+scan):   %'8d req/s           │\n" "$WAF_RPS"
printf "│   Cache hit (4KB JS):     %'8d req/s           │\n" "$CACHE_RPS"
echo "│ STATIC FILES                                       │"
printf "│   JS  4KB (upstream):     %'8d req/s           │\n" "$JS_RPS"
printf "│   PNG 8KB (upstream):     %'8d req/s           │\n" "$PNG_RPS"
printf "│   Font 16KB (cached):     %'8d req/s           │\n" "$FONT_RPS"
printf "│   CSS 3KB (cached):       %'8d req/s           │\n" "$CSS_RPS"
echo "│ SECURITY                                           │"
printf "│   SQLi blocked:           %-24s│\n" "$([ $SQLI_OK -eq 1 ] && echo 'YES' || echo 'NO ⚠')"
printf "│   XSS blocked:            %-24s│\n" "$([ $XSS_OK -eq 1 ] && echo 'YES' || echo 'NO ⚠')"
printf "│   Security status:        %-24s│\n" "$SEC_STATUS"
echo "└────────────────────────────────────────────────────┘"

# ============================================================================
# HISTORY
# ============================================================================

if [[ -f "$HISTORY_FILE" ]]; then
    python3 -c "
import json
entry = json.loads('''$RESULT_JSON''')
with open('$HISTORY_FILE') as f:
    history = json.load(f)
history.append(entry)
history = history[-50:]
with open('$HISTORY_FILE', 'w') as f:
    json.dump(history, f, indent=2)
"
else
    echo "[$RESULT_JSON]" > "$HISTORY_FILE"
fi
log "Result appended to $HISTORY_FILE"

# ============================================================================
# SECURITY GATE (hard fail)
# ============================================================================

if [[ "$SEC_STATUS" == "FAIL" ]]; then
    echo ""
    echo "SECURITY GATE FAILED — WAF not blocking attacks"
    exit 1
fi

# ============================================================================
# REGRESSION CHECK
# ============================================================================

if [[ -f "$HISTORY_FILE" ]]; then
    RESULT=$(python3 -c "
import json, sys

with open('$HISTORY_FILE') as f:
    history = json.load(f)

if len(history) < 2:
    print(0)
    sys.exit(0)

current = history[-1]
recent = [h for h in history[-6:-1] if h.get('arch') == current.get('arch', 'native')]
if not recent:
    print(0)
    sys.exit(0)

metrics = ['tls_proxy_rps', 'html_rps', 'waf_post_rps', 'cache_hit_rps', 'js_rps', 'css_rps']
names =   ['TLS proxy',     'HTML',     'WAF POST',      'Cache hit',     'JS',     'CSS']
threshold = $REGRESSION_THRESHOLD
regression = 0

for metric, name in zip(metrics, names):
    vals = [h[metric] for h in recent if metric in h and h[metric] > 0]
    if not vals: continue
    baseline = max(vals)
    current_val = current.get(metric, 0)
    if baseline > 0 and current_val > 0:
        delta = ((current_val / baseline) - 1) * 100
        if delta < -threshold:
            print(f'  REGRESSION: {name}: {current_val} vs {baseline} ({delta:+.1f}%)', file=sys.stderr)
            regression = 1
        elif delta > threshold:
            print(f'  IMPROVEMENT: {name}: {current_val} vs {baseline} ({delta:+.1f}%)', file=sys.stderr)

print(regression)
" 2>&1)

    if echo "$RESULT" | grep -q "REGRESSION"; then
        echo ""
        echo "$RESULT"
        echo ""
        echo "BENCHMARK REGRESSION DETECTED (>${REGRESSION_THRESHOLD}% drop)"
        exit 1
    elif echo "$RESULT" | grep -q "IMPROVEMENT"; then
        echo ""
        echo "$RESULT"
    fi
fi

log "No regression detected. Smoke test passed."
