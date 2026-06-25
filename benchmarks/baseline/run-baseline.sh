#!/usr/bin/env bash
# =============================================================================
# Zion edge baseline harness v2 — rigorous, reproducible benchmark + RFC
# conformance + cache-correctness, rendered to a tracked PDF.
#
# Improvements over v1 (all addressing the v1 adversarial review):
#   - N trials per measurement → median + stdev + 95% CI (v1 hid ~2x variance)
#   - full latency percentiles p50/p99/p99.9/p99.99 (v1 showed only avg/max)
#   - protocol pinned & recorded per tool (v1 mislabelled oha as "H1")
#   - nginx comparison leg on identical box/payload (v1 had no reference point)
#   - CPU% / RSS / req-per-core resource accounting (v1 had none)
#   - cache-correctness suite: Age monotonic, origin-TTL honoured, stale-born
#     passthrough, hit-ratio under load (v1 verified only "Age present")
#   - concurrency sweep → latency/throughput curve (v1 had one operating point)
#   - payload matrix 1K/64K/1M (v1 used one tiny body)
#   - regression delta vs stored history
#   - optional CO-corrected load (wrk2), all optional legs SKIP-logged, never
#     silently dropped
#
# Run on an ISOLATED host (dedicated LXC/VM, fixed CPU governor) for authoritative
# numbers — a busy laptop thermally throttles and the numbers are not defensible.
#
# Usage:
#   MODE=full  bash benchmarks/baseline/run-baseline.sh    # authoritative (LXC)
#   MODE=smoke bash benchmarks/baseline/run-baseline.sh    # fast pipeline check
#
# Requires: cargo go openssl jq python3 ; oha h2load wrk ; weasyprint (CLI).
# Optional (SKIP-logged if absent): nginx, wrk2, h2spec, testssl.sh, matplotlib.
# =============================================================================
set -euo pipefail

MODE="${MODE:-full}"
case "$MODE" in
  full)  TRIALS="${TRIALS:-5}";  DURATION="${DURATION:-20s}"; SWEEP="${SWEEP:-1 10 50 100 250 500}"; PAYLOADS="${PAYLOADS:-1024 65536 1048576}";;
  smoke) TRIALS="${TRIALS:-2}";  DURATION="${DURATION:-5s}";  SWEEP="${SWEEP:-1 50}";               PAYLOADS="${PAYLOADS:-1024 65536}";;
  *) echo "MODE must be full|smoke"; exit 2;;
esac
CONNS="${CONNS:-50}"
WRK_THREADS="${WRK_THREADS:-4}"
H2LOAD_N="${H2LOAD_N:-200000}"
H2LOAD_M="${H2LOAD_M:-20}"
WARMUP="${WARMUP:-200}"
REPORT="${REPORT:-1}"          # 1=build report here; 0=measure only (render PDF elsewhere)
# CPU pinning (Linux/taskset only): keep the load generator off the server's
# cores so it can't steal CPU from zion. By default the allowed cpuset is
# auto-split in half (server | load) — this handles LXC cpusets with
# non-contiguous host core IDs (e.g. "23,31-32,34-38"). Override ZION_CPUS /
# LOAD_CPUS to pin explicitly, or set PIN=0 to disable.
PIN="${PIN:-1}"
ZION_CPUS="${ZION_CPUS:-}"
LOAD_CPUS="${LOAD_CPUS:-}"

HTTPS="https://127.0.0.1:4432"
NGINX_HTTPS="https://127.0.0.1:4433"
URL_CHUNK="$HTTPS/_next/static/chunk.js"     # default cacheable asset
URL_PROXY="$HTTPS/api/v1/data"               # proxy passthrough
HOSTPORT="127.0.0.1:4432"
blob()  { echo "/_next/static/blob?bytes=$1"; }   # cacheable sized
pblob() { echo "/api/blob?bytes=$1"; }            # proxy sized

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib.sh"
RES="$SCRIPT_DIR/results"; rm -rf "$RES"; mkdir -p "$RES"
H2SPEC_BIN="${H2SPEC:-$(command -v h2spec || echo "$HOME/http-tools/h2spec")}"

# ── Preflight ───────────────────────────────────────────────────────────────
for t in cargo go openssl python3 oha h2load wrk; do have "$t" || die "missing required tool: $t"; done
[ "$REPORT" = 1 ] && { have weasyprint || die "weasyprint missing (set REPORT=0 to measure only and render elsewhere)"; }
# CPU pinning prefixes. Auto-derive from the allowed cpuset unless overridden;
# validate each set with a no-op taskset and fall back to no pinning if the
# kernel/container rejects it.
PIN_ZION=""; PIN_LOAD=""
if [ "$PIN" = 1 ] && have taskset; then
  if [ -z "$ZION_CPUS" ] && [ -z "$LOAD_CPUS" ]; then
    allowed="$(cat /sys/fs/cgroup/cpuset.cpus.effective 2>/dev/null || cat /sys/devices/system/cpu/online 2>/dev/null || echo)"
    flat="$(python3 -c "
import sys
o=[]
for p in sys.argv[1].split(','):
    if '-' in p: a,b=p.split('-'); o+=range(int(a),int(b)+1)
    elif p.strip(): o.append(int(p))
print(' '.join(map(str,o)))" "$allowed" 2>/dev/null)"
    set -- $flat; n=$#
    if [ "$n" -ge 4 ]; then
      h=$((n/2)); first=""; second=""; i=0
      for c in $flat; do i=$((i+1)); if [ "$i" -le "$h" ]; then first="$first,$c"; else second="$second,$c"; fi; done
      ZION_CPUS="${first#,}"; LOAD_CPUS="${second#,}"
    else
      skip "only $n CPUs allowed → no pinning"
    fi
  fi
  if [ -n "$ZION_CPUS" ] && taskset -c "$ZION_CPUS" true 2>/dev/null && taskset -c "$LOAD_CPUS" true 2>/dev/null; then
    PIN_ZION="taskset -c $ZION_CPUS"; PIN_LOAD="taskset -c $LOAD_CPUS"
  else
    skip "taskset rejected cpuset ($ZION_CPUS | $LOAD_CPUS) → no CPU pinning"
    ZION_CPUS=""; LOAD_CPUS=""
  fi
else
  [ "$PIN" = 1 ] && skip "taskset absent → no CPU pinning (load and server share cores)"
fi
OPT_NGINX=$(have nginx && echo 1 || echo 0)
OPT_WRK2=$(have wrk2 && echo 1 || echo 0)
OPT_H2SPEC=$([ -x "$H2SPEC_BIN" ] && echo 1 || echo 0)
OPT_TESTSSL=$(have testssl.sh && echo 1 || echo 0)
OPT_MPL=$(python3 -c 'import matplotlib' 2>/dev/null && echo 1 || echo 0)
[ "$OPT_NGINX" = 1 ]  || skip "nginx missing → no comparison leg"
[ "$OPT_WRK2" = 1 ]   || skip "wrk2 missing → no CO-corrected latency leg"
[ "$OPT_H2SPEC" = 1 ] || skip "h2spec missing → no HTTP/2 conformance"
[ "$OPT_TESTSSL" = 1 ]|| skip "testssl.sh missing → no TLS conformance"
[ "$OPT_MPL" = 1 ]    || skip "matplotlib missing → sweep rendered as table, no chart"

# ── Build + certs ───────────────────────────────────────────────────────────
log "building zion (release)"; cargo build --release >/dev/null 2>&1 || die "zion build failed"
ZION_BIN="$REPO_ROOT/target/release/zion"
bash benchmarks/certs/generate.sh >/dev/null 2>&1 || true
[ -f benchmarks/certs/tls.crt ] || die "cert generation failed"

# ── Environment capture ─────────────────────────────────────────────────────
log "recording environment"
GOV="unknown"
[ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ] && GOV="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
{
  echo "mode=$MODE"
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "git_sha=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  echo "git_dirty=$(test -n "$(git status --porcelain 2>/dev/null)" && echo yes || echo no)"
  echo "zion_version=$("$ZION_BIN" --version 2>&1 | head -1)"
  echo "os=$(uname -sr)"; echo "arch=$(uname -m)"
  echo "cpu_governor=$GOV"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "cpu=$(sysctl -n machdep.cpu.brand_string 2>/dev/null)"; echo "cores=$(sysctl -n hw.ncpu)"
    echo "mem_gb=$(( $(sysctl -n hw.memsize) / 1024/1024/1024 ))"
    echo "isolation=laptop/shared (NOT isolated — numbers indicative only)"
  else
    echo "cpu=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"; echo "cores=$(nproc)"
    echo "mem_gb=$(( $(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024/1024 ))"
    echo "isolation=$([ "$GOV" = performance ] && echo 'governor=performance' || echo "governor=$GOV (set 'performance' for best repeatability)")"
  fi
  echo "tool_oha=$(oha --version 2>&1 | head -1)"
  echo "tool_h2load=$(h2load --version 2>&1 | head -1)"
  echo "tool_wrk=$(wrk --version 2>&1 | head -1 || true)"
  [ "$OPT_WRK2" = 1 ]   && echo "tool_wrk2=$(wrk2 --version 2>&1 | head -1 || echo present)"
  [ "$OPT_NGINX" = 1 ]  && echo "tool_nginx=$(nginx -v 2>&1 | head -1)"
  [ "$OPT_H2SPEC" = 1 ] && echo "tool_h2spec=$("$H2SPEC_BIN" --version 2>&1 | head -1)"
  [ "$OPT_TESTSSL" = 1 ]&& echo "tool_testssl=$(testssl.sh --version 2>&1 | sed $'s/\x1b\\[[0-9;]*m//g' | grep -iE 'version' | head -1)"
  echo "tool_openssl=$(openssl version)"
  echo "params_trials=$TRIALS"; echo "params_duration=$DURATION"; echo "params_conns=$CONNS"
  echo "params_sweep=$SWEEP"; echo "params_payloads=$PAYLOADS"
  echo "params_h2load_n=$H2LOAD_N"; echo "params_h2load_m=$H2LOAD_M"
  echo "pin_zion=${PIN_ZION:-none}"; echo "pin_load=${PIN_LOAD:-none}"
} > "$RES/meta.env"

# ── Lab up + teardown ───────────────────────────────────────────────────────
cleanup() { for p in "${ZION_PID:-}" "${BE_PID:-}" "${NGINX_PID:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  lsof -ti:9090,4432,8082,4433 2>/dev/null | xargs kill -9 2>/dev/null || true; }
trap cleanup EXIT
lsof -ti:9090,4432,8082,4433 2>/dev/null | xargs kill -9 2>/dev/null || true

log "starting bench backend (:9090)${PIN_ZION:+ [$PIN_ZION]}"
( cd benchmarks/backend && $PIN_ZION go run main.go ) > "$RES/backend.log" 2>&1 & BE_PID=$!
log "starting zion (:4432)${PIN_ZION:+ [$PIN_ZION]}"
ZION_CONFIG="$SCRIPT_DIR/zion-lab.toml" $PIN_ZION "$ZION_BIN" > "$RES/zion.log" 2>&1 & ZION_PID=$!
for i in $(seq 1 30); do curl -sk -o /dev/null --max-time 2 "$URL_PROXY" 2>/dev/null && break; sleep 0.5; [ "$i" = 30 ] && die "lab not ready"; done

if [ "$OPT_NGINX" = 1 ]; then
  log "starting nginx comparison (:4433, proxy_cache → backend)"
  cat > "$RES/nginx.conf" <<NGINX
worker_processes auto; error_log /dev/null; pid $RES/nginx.pid; daemon off;
events { worker_connections 4096; }
http {
  access_log off;
  proxy_cache_path $RES/ngxcache levels=1:2 keys_zone=z:10m max_size=512m inactive=1h;
  upstream be { server 127.0.0.1:9090; keepalive 64; }
  server {
    listen 4433 ssl http2;
    ssl_certificate $REPO_ROOT/benchmarks/certs/tls.crt;
    ssl_certificate_key $REPO_ROOT/benchmarks/certs/tls.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    location /_next/static/ { proxy_pass http://be; proxy_cache z; proxy_cache_valid 200 1h;
      proxy_http_version 1.1; proxy_set_header Connection ""; add_header X-Cache \$upstream_cache_status; }
    location / { proxy_pass http://be; proxy_http_version 1.1; proxy_set_header Connection ""; }
  }
}
NGINX
  $PIN_ZION nginx -c "$RES/nginx.conf" -p "$RES" > "$RES/nginx.log" 2>&1 & NGINX_PID=$!
  sleep 1
  curl -sk -o /dev/null --max-time 3 "$NGINX_HTTPS/_next/static/chunk.js" 2>/dev/null || { skip "nginx did not come up; disabling comparison"; OPT_NGINX=0; }
fi

# ── Protocol probe (record what each endpoint negotiates) ───────────────────
proto() { curl -sk -o /dev/null -w '%{http_version}' --max-time 5 "$1" 2>/dev/null; }
{ echo "zion_alpn=$(proto "$URL_CHUNK")"; echo "nginx_alpn=$([ "$OPT_NGINX" = 1 ] && proto "$NGINX_HTTPS/_next/static/chunk.js" || echo n/a)"; } > "$RES/proto.env"

# ── Cache-correctness suite (validates the v0.4.2 fix) ──────────────────────
log "cache-correctness checks"
getage() { curl -sk -D - -o /dev/null "$1" | awk 'tolower($1)=="age:"{print $2}' | tr -d '\r'; }
{
  # Prime robustly: the cache insert runs in an async tee task after the first
  # response streams, so a single prime can race the measuring request. Poll
  # until Age appears (cache populated) or give up after ~3s.
  for _ in $(seq 1 30); do curl -sk -o /dev/null "$URL_CHUNK"; [ -n "$(getage "$URL_CHUNK")" ] && break; sleep 0.1; done
  a1=$(getage "$URL_CHUNK")
  sleep 2
  a2=$(getage "$URL_CHUNK")
  echo "age_present=$([ -n "$a1" ] && echo yes || echo no)"
  echo "age_t0=$a1"; echo "age_t2=$a2"
  echo "age_monotonic=$([ -n "$a1" ] && [ -n "$a2" ] && [ "$a2" -ge "$a1" ] && echo yes || echo no)"
  # origin TTL honoured: backend max-age=5 → zion must emit max-age=5
  curl -sk -o /dev/null "$HTTPS/_next/static/shortttl"
  cc=$(curl -sk -D - -o /dev/null "$HTTPS/_next/static/shortttl" | awk 'tolower($1)=="cache-control:"{$1="";print}' | tr -d '\r' | xargs)
  echo "shortttl_cache_control=$cc"
  echo "origin_ttl_honored=$(echo "$cc" | grep -q 'max-age=5' && echo yes || echo no)"
  # stale-born: backend Age:99999 + max-age=10 → zion forwards (does not freeze a young entry)
  sb=$(curl -sk -D - -o /dev/null "$HTTPS/_next/static/staleborn" | awk 'tolower($1)=="age:"{print $2}' | tr -d '\r')
  echo "staleborn_age=$sb"
  echo "staleborn_passthrough=$([ -n "$sb" ] && [ "$sb" -ge 99999 ] && echo yes || echo no)"
} > "$RES/cache-correctness.txt" 2>&1

# hit-ratio under 90/10 hot/cold load: scrape zion metrics delta
log "cache hit-ratio under load"
metric() { curl -sk "http://127.0.0.1:8082/metrics" 2>/dev/null | awk -v k="$1" '$1==k{print $2}'; }
# 90/10 hot/cold. Each curl is a fresh TLS handshake (no keepalive); the whole
# leg is wall-clock-capped so it can NEVER stall the run on a slow/contended box
# (where curls may hit --max-time) — we measure the ratio from whatever
# completed within the window. The 90/10 ratio, not absolute volume, is the point.
case "$MODE" in full) HOT=450; COLD=50;; *) HOT=180; COLD=20;; esac
h0=$(metric zion_cache_hits); m0=$(metric zion_cache_misses)
: "${h0:=0}"; : "${m0:=0}"
timeout "${HITRATIO_SECS:-90}" bash -c '
  H='"$HOT"'; C='"$COLD"'; U="'"$HTTPS"'"
  for _ in $(seq 1 "$H"); do curl -sk --max-time 3 -o /dev/null "$U/_next/static/blob?bytes=$((1024 + RANDOM % 50))"; done &
  for i in $(seq 1 "$C"); do curl -sk --max-time 3 -o /dev/null "$U/_next/static/blob?bytes=$((100000 + i))"; done
  wait
' 2>/dev/null || true
h1=$(metric zion_cache_hits); m1=$(metric zion_cache_misses)
: "${h1:=0}"; : "${m1:=0}"
{ echo "hits_delta=$((h1 - h0))"; echo "misses_delta=$((m1 - m0))"
  echo "hit_ratio=$(awk -v h=$((h1-h0)) -v m=$((m1-m0)) 'BEGIN{t=h+m; printf (t>0)?"%.1f":"n/a", (t>0)?100*h/t:0}')"
} >> "$RES/cache-correctness.txt"

# ── Conformance ─────────────────────────────────────────────────────────────
[ "$OPT_H2SPEC" = 1 ] && { log "h2spec"; "$H2SPEC_BIN" -t -k -h 127.0.0.1 -p 4432 > "$RES/h2spec.txt" 2>&1 || true; }
[ "$OPT_TESTSSL" = 1 ] && { log "testssl (slow)"; testssl.sh --quiet --color 0 --jsonfile "$RES/testssl.json" "$HOSTPORT" > "$RES/testssl.txt" 2>&1 || true; }

# ── Benchmark helpers ───────────────────────────────────────────────────────
# Run oha N trials against URL with concurrent resource sampling of $pid; append
# one "rps p50 p99 p999 p9999 cpu rssmb" line per trial to $out.
bench_oha() {
  local url="$1" out="$2" pid="${3:-$ZION_PID}"; : > "$out"
  # A leg that errors (e.g. the optional nginx target refusing oha) must NOT
  # abort the whole run under `set -e` — tolerate per-request and per-oha
  # failures and let the row fall to zeros, which the report renders as absent.
  for _ in $(seq 1 "$WARMUP"); do curl -sk -o /dev/null "$url" || true; done
  for _ in $(seq 1 "$TRIALS"); do
    local rfile; rfile=$(mktemp)
    local dsec="${DURATION%s}"
    sample_proc "$pid" "$dsec" "$rfile" &
    local sp=$!
    local o; o=$($PIN_LOAD oha -z "$DURATION" -c "$CONNS" --insecure --no-tui "$url" 2>&1 || true)
    wait "$sp" 2>/dev/null || true
    local rps p50 p99 p999 p9999 cpu rss
    rps=$(awk '/Requests\/sec:/{print $2}' <<<"$o")
    p50=$(awk '/50\.00%/{print $3}'  <<<"$o"); p99=$(awk '/99\.00%/{print $3}'  <<<"$o")
    p999=$(awk '/99\.90%/{print $3}' <<<"$o"); p9999=$(awk '/99\.99%/{print $3}' <<<"$o")
    # `read` returns non-zero on an empty rfile (sample_proc couldn't read the
    # pid — e.g. a daemonized/exited process), which would abort under set -e.
    read -r cpu rss < "$rfile" 2>/dev/null || true; rm -f "$rfile"
    cpu="${cpu:-0}"; rss="${rss:-0}"
    echo "${rps:-0} ${p50:-0} ${p99:-0} ${p999:-0} ${p9999:-0} ${cpu:-0} ${rss:-0}" >> "$out"
  done
}

log "headline: zion cache-hit ($TRIALS trials, c=$CONNS, $DURATION)"
bench_oha "$URL_CHUNK" "$RES/hl-zion-cache.dat"
log "headline: zion proxy passthrough"
bench_oha "$URL_PROXY" "$RES/hl-zion-proxy.dat"
if [ "$OPT_NGINX" = 1 ]; then
  log "headline: nginx cache-hit (comparison)"
  bench_oha "$NGINX_HTTPS/_next/static/chunk.js" "$RES/hl-nginx-cache.dat" "$NGINX_PID"
fi

log "concurrency sweep (zion cache-hit)"
: > "$RES/sweep.dat"
for c in $SWEEP; do
  for _ in $(seq 1 "$WARMUP"); do curl -sk -o /dev/null "$URL_CHUNK" || true; done
  o=$($PIN_LOAD oha -z "$DURATION" -c "$c" --insecure --no-tui "$URL_CHUNK" 2>&1 || true)
  rps=$(awk '/Requests\/sec:/{print $2}' <<<"$o"); p99=$(awk '/99\.00%/{print $3}' <<<"$o")
  echo "$c ${rps:-0} ${p99:-0}" >> "$RES/sweep.dat"
done

log "payload matrix (zion cache-hit, $TRIALS trials)"
: > "$RES/payload.dat"
for p in $PAYLOADS; do
  bench_oha "$HTTPS$(blob "$p")" "$RES/pm-$p.dat"
  echo "$p" >> "$RES/payload.dat"   # medians computed in build-report.py from pm-<p>.dat
done

# ── Protocol-pinned coverage (explicit H2 + H1) ─────────────────────────────
log "h2load (explicit HTTP/2)"
$PIN_LOAD h2load -n "$H2LOAD_N" -c "$CONNS" -m "$H2LOAD_M" "$URL_CHUNK" > "$RES/h2load.txt" 2>&1
log "wrk (explicit HTTP/1.1)"
$PIN_LOAD wrk -t"$WRK_THREADS" -c"$CONNS" -d"$DURATION" "$URL_CHUNK" > "$RES/wrk.txt" 2>&1
if [ "$OPT_WRK2" = 1 ]; then
  log "wrk2 (CO-corrected, rate=50k)"
  $PIN_LOAD wrk2 -t"$WRK_THREADS" -c"$CONNS" -d"$DURATION" -R50000 --latency "$URL_CHUNK" > "$RES/wrk2.txt" 2>&1 || true
fi

# ── Report ──────────────────────────────────────────────────────────────────
if [ "$REPORT" = 1 ]; then
  log "regression delta + report"
  python3 "$SCRIPT_DIR/build-report.py" "$RES" "$SCRIPT_DIR" "$SCRIPT_DIR/history.json" > "$RES/_pdfname" 2>"$RES/_builderr" || { cat "$RES/_builderr"; die "report build failed"; }
  PDF_NAME="$(tail -1 "$RES/_pdfname")"
  log "rendering PDF ($PDF_NAME)"
  weasyprint "$SCRIPT_DIR/report.html" "$SCRIPT_DIR/$PDF_NAME" 2>/dev/null || die "weasyprint failed"
  log "DONE — benchmarks/baseline/$PDF_NAME"
else
  log "MEASURE-ONLY (REPORT=0) — raw results in $RES/. Render the PDF elsewhere:"
  log "  rsync the results/ dir to a host with weasyprint+matplotlib, then:"
  log "  python3 build-report.py results . history.json && weasyprint report.html zion-<ver>-baseline.pdf"
fi
