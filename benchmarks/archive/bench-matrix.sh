#!/usr/bin/env bash
set -euo pipefail

# ════════════════════════════════════════════════════════════════════════════
# ZION MATRIX BENCHMARK — Scientific Payload × Concurrency Grid
#
# Methodology:
#   - Each cell runs WARMUP + MEASURE rounds of wrk
#   - Warmup rounds discarded (JIT, TCP slow-start, cache priming)
#   - Measure rounds averaged; σ (std-dev) computed for confidence
#   - Results: req/s, throughput, avg/p99 latency, errors
#   - Automatic delta comparison with previous run
#
# Grid:
#   Clients:   1, 10, 100
#   Payloads:  1MB, 10MB, 100MB
#   Modes:     dynamic uncached, static uncached,
#              dynamic cache-proxy, static cached (RAM)
#
# Usage:
#   ./bench-matrix.sh                 # full run (~8 min)
#   ./bench-matrix.sh --quick         # 1 round × 3s (~2 min)
#   ./bench-matrix.sh --duration 10   # 10s per round
#   ./bench-matrix.sh --rounds 5      # 5 measure rounds
#
# Exit: 0=ok, 2=infra error
# ════════════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
HISTORY_FILE="$RESULTS_DIR/matrix-history.json"

# ── Tunables ───────────────────────────────────────────────────────────────
DURATION=5
WARMUP_ROUNDS=1
MEASURE_ROUNDS=3
CLIENTS="1 10 100"
PAYLOAD_BYTES="1048576 10485760 104857600"
PAYLOAD_LABELS="1MB 10MB 100MB"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration) DURATION="$2";       shift 2 ;;
        --rounds)   MEASURE_ROUNDS="$2"; shift 2 ;;
        --warmup)   WARMUP_ROUNDS="$2";  shift 2 ;;
        --quick)    WARMUP_ROUNDS=0; MEASURE_ROUNDS=1; DURATION=3; shift ;;
        -h|--help)  sed -n '3,25p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *)          echo "Unknown: $1" >&2; exit 1 ;;
    esac
done

# Counts — bash 3.2 safe
N_CLIENTS=$(echo $CLIENTS | wc -w | tr -d ' ')
N_PAYLOADS=$(echo $PAYLOAD_LABELS | wc -w | tr -d ' ')
TOTAL_ROUNDS=$((WARMUP_ROUNDS + MEASURE_ROUNDS))
TOTAL_CELLS=$(( N_CLIENTS * N_PAYLOADS * 4 ))
TOTAL_WRK=$(( TOTAL_CELLS * TOTAL_ROUNDS ))

# ── Infra PIDs ─────────────────────────────────────────────────────────────
BACKEND_PID=""
ZION_PID_NC=""
ZION_PID_C=""

# ── Data store (temp dir, bash 3.2 compatible) ────────────────────────────
DATA_DIR=$(mktemp -d)
data_put() { echo "$2" > "$DATA_DIR/$1"; }
data_get() { cat "$DATA_DIR/$1" 2>/dev/null || echo "0"; }

# ── Colors ────────────────────────────────────────────────────────────────
if [[ -t 1 ]] && command -v tput &>/dev/null && [[ $(tput colors 2>/dev/null || echo 0) -ge 8 ]]; then
    B=$(tput bold) D=$(tput dim) R=$(tput sgr0)
    CR=$(tput setaf 1) CG=$(tput setaf 2) CY=$(tput setaf 3) CC=$(tput setaf 6)
else
    B="" D="" R="" CR="" CG="" CY="" CC=""
fi

# ── Helpers ────────────────────────────────────────────────────────────────
ts()  { date +%H:%M:%S; }
log() { printf "  ${D}%s${R} %s\n" "$(ts)" "$*"; }
die() { printf "  ${CR}FATAL${R} %s\n" "$*" >&2; cleanup; exit 2; }

cleanup() {
    [[ -n "$ZION_PID_NC" ]] && kill "$ZION_PID_NC" 2>/dev/null || true
    [[ -n "$ZION_PID_C" ]]  && kill "$ZION_PID_C"  2>/dev/null || true
    [[ -n "$BACKEND_PID" ]] && kill "$BACKEND_PID"  2>/dev/null || true
    rm -rf "$DATA_DIR" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

wait_for_port() {
    local i=0; while ! nc -z "$1" "$2" 2>/dev/null; do
        i=$((i+1)); [[ $i -ge 20 ]] && die "Timeout: $1:$2"; sleep 0.3
    done
}
wait_for_https() {
    local i=0; while ! curl -sk --max-time 2 "$1" >/dev/null 2>&1; do
        i=$((i+1)); [[ $i -ge 20 ]] && die "Timeout: $1"; sleep 0.3
    done
}

# ── Formatting ────────────────────────────────────────────────────────────

fmt_num() {
    # macOS printf supports %'d for thousand separators
    printf "%'.0f" "${1:-0}" 2>/dev/null || echo "${1:-0}"
}

fmt_bytes() {
    local b=${1:-0}
    python3 -c "
b=$b
if b >= 1073741824:   print(f'{b/1073741824:.2f} GB/s')
elif b >= 1048576:    print(f'{b/1048576:.1f} MB/s')
elif b >= 1024:       print(f'{b/1024:.0f} KB/s')
else:                 print(f'{b} B/s')
" 2>/dev/null || echo "${b} B/s"
}

fmt_lat() {
    local us=${1:-0}
    [[ "$us" == "0" ]] && { echo "—"; return; }
    python3 -c "
us=$us
if us >= 1000000:  print(f'{us/1000000:.2f}s')
elif us >= 1000:   print(f'{us/1000:.2f}ms')
else:              print(f'{us:.0f}μs')
" 2>/dev/null || echo "${us}μs"
}

normalize_lat_us() {
    local val="$1"
    [[ -z "$val" || "$val" == "?" ]] && { echo "0"; return; }
    python3 -c "
import re
m = re.match(r'([\d.]+)(us|ms|s)', '$val')
if not m: print(0)
else:
    n, u = float(m.group(1)), m.group(2)
    print(int(n if u=='us' else n*1000 if u=='ms' else n*1000000))
" 2>/dev/null || echo "0"
}

normalize_bps() {
    local val="$1"
    [[ -z "$val" || "$val" == "?" ]] && { echo "0"; return; }
    python3 -c "
import re
m = re.match(r'([\d.]+)(GB|MB|KB|B)', '$val')
if not m: print(0)
else:
    n, u = float(m.group(1)), m.group(2)
    mult = {'GB':1073741824,'MB':1048576,'KB':1024,'B':1}
    print(int(n * mult.get(u,1)))
" 2>/dev/null || echo "0"
}

# ── wrk runner — returns pipe-delimited raw metrics ───────────────────────
wrk_raw() {
    local url=$1 conns=$2
    local threads=2; [[ $conns -le 1 ]] && threads=1
    local out; out=$(mktemp)

    wrk -t"$threads" -c"$conns" -d"${DURATION}s" --latency \
        -H "Host: bench.local" "$url" > "$out" 2>&1

    local rps=$(grep "Requests/sec:" "$out" | awk '{printf "%.2f", $2}')
    local lat_avg=$(grep "^[[:space:]]*Latency" "$out" | head -1 | awk '{print $2}')
    local lat_p99=$(grep "99%" "$out" | awk '{print $2}')
    local transfer=$(grep "Transfer/sec:" "$out" | awk '{print $2}')
    local errors=$(grep -c "Socket errors\|Non-2xx" "$out" || true)

    local lat_us=$(normalize_lat_us "$lat_avg")
    local p99_us=$(normalize_lat_us "$lat_p99")
    local bps=$(normalize_bps "$transfer")

    rm -f "$out"
    echo "${rps:-0}|${bps:-0}|${lat_us:-0}|${p99_us:-0}|${errors:-0}"
}

# ── Multi-round cell measurement ─────────────────────────────────────────
# Output: avg_rps|avg_bps|avg_lat|avg_p99|total_err|stddev
measure_cell() {
    local url=$1 conns=$2

    # Warmup
    local w=0; while [[ $w -lt $WARMUP_ROUNDS ]]; do
        wrk_raw "$url" "$conns" >/dev/null; w=$((w+1))
    done

    # Measure
    local sum_rps=0 sum_bps=0 sum_lat=0 sum_p99=0 sum_err=0
    local rps_list=""
    local m=0; while [[ $m -lt $MEASURE_ROUNDS ]]; do
        raw=$(wrk_raw "$url" "$conns")
        r=$(echo "$raw" | cut -d'|' -f1)
        b=$(echo "$raw" | cut -d'|' -f2)
        l=$(echo "$raw" | cut -d'|' -f3)
        p=$(echo "$raw" | cut -d'|' -f4)
        e=$(echo "$raw" | cut -d'|' -f5)
        sum_rps=$(echo "$sum_rps + $r" | bc -l)
        sum_bps=$(echo "$sum_bps + $b" | bc -l)
        sum_lat=$(echo "$sum_lat + $l" | bc -l)
        sum_p99=$(echo "$sum_p99 + $p" | bc -l)
        sum_err=$((sum_err + e))
        rps_list="$rps_list $r"
        m=$((m+1))
    done

    local avg_rps=$(printf "%.0f" "$(echo "$sum_rps / $MEASURE_ROUNDS" | bc -l)")
    local avg_bps=$(printf "%.0f" "$(echo "$sum_bps / $MEASURE_ROUNDS" | bc -l)")
    local avg_lat=$(printf "%.0f" "$(echo "$sum_lat / $MEASURE_ROUNDS" | bc -l)")
    local avg_p99=$(printf "%.0f" "$(echo "$sum_p99 / $MEASURE_ROUNDS" | bc -l)")

    # Std-dev via python (reliable math)
    local stddev=0
    if [[ $MEASURE_ROUNDS -gt 1 ]]; then
        stddev=$(python3 -c "
import statistics
vals = [float(x) for x in '$rps_list'.split() if x]
print(int(statistics.stdev(vals)) if len(vals)>1 else 0)
" 2>/dev/null || echo "0")
    fi

    echo "${avg_rps}|${avg_bps}|${avg_lat}|${avg_p99}|${sum_err}|${stddev}"
}

# ── Table rendering ───────────────────────────────────────────────────────
W=90

hline()   { printf "  ${D}"; printf '─%.0s' $(seq 1 $W); printf "${R}\n"; }
dotline() { printf "  ${D}"; local i=0; while [[ $i -lt $((W/2)) ]]; do printf "· "; i=$((i+1)); done; printf "${R}\n"; }

section_header() {
    echo ""
    printf "  ${B}${CC}%s${R}\n" "$1"
    printf "  ${D}%s${R}\n" "$2"
    hline
    printf "  ${B}%-8s  %5s │ %13s %9s │ %10s  %10s │ %4s${R}\n" \
           "PAYLOAD" "CONNS" "REQ/S" "±σ" "AVG LAT" "P99 LAT" "ERR"
    hline
}

result_row() {
    local plbl=$1 conns=$2 rps=$3 sd=$4 lat=$5 p99=$6 errs=$7
    local ec=""; [[ "$errs" -gt 0 ]] && ec="$CR"
    printf "  %-8s  %5s │ %13s ${D}%9s${R} │ %10s  %10s │ ${ec}%4s${R}\n" \
           "$plbl" "$conns" "$(fmt_num "$rps")" "±$(fmt_num "$sd")" \
           "$(fmt_lat "$lat")" "$(fmt_lat "$p99")" "$errs"
}

# ── Progress ──────────────────────────────────────────────────────────────
CELL_NUM=0
START_EPOCH=$(date +%s)

show_progress() {
    CELL_NUM=$((CELL_NUM + 1))
    local elapsed=$(( $(date +%s) - START_EPOCH ))
    local eta=0
    [[ $CELL_NUM -gt 1 ]] && eta=$(( elapsed * TOTAL_CELLS / (CELL_NUM - 1) - elapsed ))
    [[ $eta -lt 0 ]] && eta=0
    printf "\r  ${D}[%d/%d] %-30s  ETA %dm%02ds${R}" \
           "$CELL_NUM" "$TOTAL_CELLS" "$1" "$((eta/60))" "$((eta%60))" >&2
}
clear_progress() { printf "\r%-80s\r" "" >&2; }

# ══════════════════════════════════════════════════════════════════════════
# SETUP
# ══════════════════════════════════════════════════════════════════════════

COMMIT=$(cd "$PROJECT_DIR" && git rev-parse --short HEAD 2>/dev/null || echo "?")
BRANCH=$(cd "$PROJECT_DIR" && git branch --show-current 2>/dev/null || echo "?")
OS_INFO=$(uname -ms)
CPU_INFO=$(sysctl -n machdep.cpu.brand_string 2>/dev/null \
    || grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | sed 's/.*: //' \
    || echo "unknown")
CPU_SHORT=$(echo "$CPU_INFO" | sed 's/Apple //;s/Intel(R) Core(TM) //' | cut -c1-40)

echo ""
echo "${B}┌──────────────────────────────────────────────────────────────────────────────────────────┐${R}"
echo "${B}│${R}                                                                                          ${B}│${R}"
echo "${B}│${R}   ${CC}╔═╗╦╔═╗╔╗╔${R}  ${B}Matrix Benchmark${R}                                                        ${B}│${R}"
echo "${B}│${R}   ${CC}╔═╝║║ ║║║║${R}  Payload × Concurrency × Cache                                          ${B}│${R}"
echo "${B}│${R}   ${CC}╚═╝╩╚═╝╝╚╝${R}                                                                        ${B}│${R}"
echo "${B}│${R}                                                                                          ${B}│${R}"
printf "${B}│${R}   Commit     ${B}%-10s${R} on %-60s${B}│${R}\n" "$COMMIT" "$BRANCH"
printf "${B}│${R}   Platform   %-74s${B}│${R}\n" "$OS_INFO · $CPU_SHORT"
printf "${B}│${R}   Date       %-74s${B}│${R}\n" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
echo "${B}│${R}                                                                                          ${B}│${R}"
printf "${B}│${R}   Grid       ${B}%s${R} concurrency × ${B}%s${R} payloads × ${B}4${R} modes = ${B}%s${R} cells%-22s${B}│${R}\n" \
       "$N_CLIENTS" "$N_PAYLOADS" "$TOTAL_CELLS" ""
printf "${B}│${R}   Rounds     %s warmup + %s measure × %ss = ${B}%s${R} wrk runs%-20s${B}│${R}\n" \
       "$WARMUP_ROUNDS" "$MEASURE_ROUNDS" "$DURATION" "$TOTAL_WRK" ""
printf "${B}│${R}   Est. time  ~%s min%-72s${B}│${R}\n" "$(( TOTAL_WRK * (DURATION + 1) / 60 ))" ""
echo "${B}│${R}                                                                                          ${B}│${R}"
echo "${B}└──────────────────────────────────────────────────────────────────────────────────────────┘${R}"
echo ""

log "Building release binary..."
cd "$PROJECT_DIR"
cargo build --release 2>&1 | tail -1

log "Starting Go backend on :9090..."
cd "$SCRIPT_DIR/backend"
go run test-server.go 2>/dev/null &
BACKEND_PID=$!
wait_for_port 127.0.0.1 9090

cd "$PROJECT_DIR"
log "Starting Zion (no-cache) on :4430..."
ZION_CONFIG=benchmarks/zion-bench-tls.toml ./target/release/zion 2>/dev/null &
ZION_PID_NC=$!
wait_for_https "https://127.0.0.1:4430/"

log "Starting Zion (cache) on :4432..."
ZION_CONFIG=benchmarks/zion-bench-tls-cache.toml ./target/release/zion 2>/dev/null &
ZION_PID_C=$!
wait_for_https "https://127.0.0.1:4432/"

log "Infrastructure ready ✓"

# ══════════════════════════════════════════════════════════════════════════
# SECTION RUNNER
# ══════════════════════════════════════════════════════════════════════════

run_section() {
    local mode=$1 title=$2 subtitle=$3 port=$4 path=$5 prime=$6

    section_header "$title" "$subtitle"

    local pi=0
    for sz in $PAYLOAD_BYTES; do
        # Get label by position
        lbl=$(echo $PAYLOAD_LABELS | cut -d' ' -f$((pi+1)))

        if [[ "$prime" == "yes" ]]; then
            curl -sk -H "Host: bench.local" "https://127.0.0.1:${port}${path}?size=${sz}" >/dev/null 2>&1 || true
        fi

        for conns in $CLIENTS; do
            show_progress "${mode} ${lbl} c=${conns}"
            local url="https://127.0.0.1:${port}${path}?size=${sz}"
            local result=$(measure_cell "$url" "$conns")

            local avg_rps=$(echo "$result" | cut -d'|' -f1)
            local avg_bps=$(echo "$result" | cut -d'|' -f2)
            local avg_lat=$(echo "$result" | cut -d'|' -f3)
            local avg_p99=$(echo "$result" | cut -d'|' -f4)
            local tot_err=$(echo "$result" | cut -d'|' -f5)
            local stddev=$(echo "$result" | cut -d'|' -f6)

            clear_progress
            result_row "$lbl" "$conns" "$avg_rps" "$stddev" "$avg_lat" "$avg_p99" "$tot_err"

            # Store metrics
            data_put "${mode}_${lbl}_c${conns}_rps" "$avg_rps"
            data_put "${mode}_${lbl}_c${conns}_bps" "$avg_bps"
            data_put "${mode}_${lbl}_c${conns}_lat" "$avg_lat"
            data_put "${mode}_${lbl}_c${conns}_p99" "$avg_p99"
            data_put "${mode}_${lbl}_c${conns}_sd"  "$stddev"
        done

        pi=$((pi+1))
        [[ $pi -lt $N_PAYLOADS ]] && dotline
    done
    hline
}

# ══════════════════════════════════════════════════════════════════════════
# 4 SECTIONS
# ══════════════════════════════════════════════════════════════════════════

run_section "dynamic" \
    "DYNAMIC (uncached)" \
    "GET /api/v1/large → Go backend ⟶ Zion TLS proxy, no caching" \
    4430 "/api/v1/large" "no"

run_section "static" \
    "STATIC (uncached)" \
    "GET /_next/static/blob → Go backend ⟶ Zion TLS proxy, no caching" \
    4430 "/_next/static/blob" "no"

run_section "dyn_cache" \
    "DYNAMIC (cache proxy)" \
    "GET /api/v1/large → Zion cache-enabled instance (API routes bypass cache)" \
    4432 "/api/v1/large" "no"

run_section "cached" \
    "STATIC CACHED (RAM)" \
    "GET /_next/static/blob → Zion in-memory cache (primed before measurement)" \
    4432 "/_next/static/blob" "yes"

# ══════════════════════════════════════════════════════════════════════════
# CACHE SPEEDUP HEATMAP
# ══════════════════════════════════════════════════════════════════════════

echo ""
printf "  ${B}${CC}CACHE SPEEDUP MATRIX${R}  ${D}cached ÷ uncached req/s${R}\n"
hline
printf "  ${B}%-10s" ""
for c in $CLIENTS; do printf "%15s" "c=$c"; done
echo "${R}"
hline

for lbl in $PAYLOAD_LABELS; do
    printf "  %-10s" "$lbl"
    for conns in $CLIENTS; do
        cr=$(data_get "cached_${lbl}_c${conns}_rps")
        sr=$(data_get "static_${lbl}_c${conns}_rps")
        if [[ "$sr" -gt 0 && "$cr" -gt 0 ]] 2>/dev/null; then
            ratio=$(echo "scale=1; $cr / $sr" | bc -l)
            col="$CY"
            [[ $(echo "$ratio >= 2" | bc -l) == "1" ]] && col="$CG"
            [[ $(echo "$ratio < 1" | bc -l) == "1" ]] && col="$CR"
            printf " ${col}%13sx${R}" "$ratio"
        else
            printf " %14s" "—"
        fi
    done
    echo ""
done
hline

# ══════════════════════════════════════════════════════════════════════════
# PEAK THROUGHPUT
# ══════════════════════════════════════════════════════════════════════════

echo ""
printf "  ${B}${CC}PEAK THROUGHPUT${R}\n"
hline

for mode in dynamic static dyn_cache cached; do
    best_rps=0 best_lbl="" best_c=""
    for lbl in $PAYLOAD_LABELS; do
        for conns in $CLIENTS; do
            rps=$(data_get "${mode}_${lbl}_c${conns}_rps")
            if [[ $rps -gt $best_rps ]] 2>/dev/null; then
                best_rps=$rps; best_lbl=$lbl; best_c=$conns
            fi
        done
    done
    bps=$(data_get "${mode}_${best_lbl}_c${best_c}_bps")
    p99=$(data_get "${mode}_${best_lbl}_c${best_c}_p99")
    mode_label=""
    case "$mode" in
        dynamic)   mode_label="Dynamic" ;;
        static)    mode_label="Static" ;;
        dyn_cache) mode_label="Dyn+Cache" ;;
        cached)    mode_label="Cached RAM" ;;
    esac
    printf "  %-12s  ${B}%13s req/s${R}  %14s  p99 %-10s  ${D}(%s c=%s)${R}\n" \
           "$mode_label" "$(fmt_num "$best_rps")" "$(fmt_bytes "$bps")" \
           "$(fmt_lat "$p99")" "$best_lbl" "$best_c"
done
hline

# ══════════════════════════════════════════════════════════════════════════
# P99 LATENCY HEATMAP
# ══════════════════════════════════════════════════════════════════════════

echo ""
printf "  ${B}${CC}P99 LATENCY HEATMAP${R}  ${D}cached static mode${R}\n"
hline
printf "  ${B}%-10s" ""
for c in $CLIENTS; do printf "%15s" "c=$c"; done
echo "${R}"
hline

for lbl in $PAYLOAD_LABELS; do
    printf "  %-10s" "$lbl"
    for conns in $CLIENTS; do
        p99=$(data_get "cached_${lbl}_c${conns}_p99")
        col=""
        [[ $p99 -gt 10000 ]]  2>/dev/null && col="$CY"
        [[ $p99 -gt 100000 ]] 2>/dev/null && col="$CR"
        printf " ${col}%14s${R}" "$(fmt_lat "$p99")"
    done
    echo ""
done
hline

# ══════════════════════════════════════════════════════════════════════════
# SAVE HISTORY & DELTA
# ══════════════════════════════════════════════════════════════════════════

mkdir -p "$RESULTS_DIR"

# Build JSON from data store
python3 << PYEOF
import os, json, glob
from datetime import datetime

data_dir = "$DATA_DIR"
results = {}
for fpath in glob.glob(os.path.join(data_dir, "*")):
    key = os.path.basename(fpath)
    with open(fpath) as f:
        try: results[key] = int(f.read().strip())
        except: results[key] = 0

entry = {
    "commit": "$COMMIT",
    "branch": "$BRANCH",
    "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    "os": "$OS_INFO",
    "cpu": """$CPU_INFO""".strip()[:60],
    "config": {"duration": $DURATION, "warmup": $WARMUP_ROUNDS, "rounds": $MEASURE_ROUNDS},
    "results": results,
}

history_file = "$HISTORY_FILE"
if os.path.exists(history_file):
    with open(history_file) as f:
        history = json.load(f)
else:
    history = []

history.append(entry)
history = history[-30:]
with open(history_file, "w") as f:
    json.dump(history, f, indent=2)

# Delta comparison — only compare runs with same config (quick vs quick, full vs full)
cur_cfg = history[-1]["config"]
comparable = [r for r in history[:-1] if r["config"] == cur_cfg]
if comparable:
    prev = comparable[-1]
    cur = history[-1]["results"]
    prev_r = prev["results"]
    prev_commit = prev.get("commit", "?")[:7]
    changes = []
    for key in sorted(cur.keys()):
        if key.endswith("_rps") and key in prev_r:
            c, p = cur[key], prev_r[key]
            if p > 0:
                pct = (c - p) * 100 / p
                if abs(pct) > 3:
                    name = key.replace("_rps", "").replace("_", " ")
                    changes.append((name, c, p, pct))

    if changes:
        print("")
        mode = "quick" if cur_cfg["rounds"] <= 1 else f"{cur_cfg['rounds']}r×{cur_cfg['duration']}s"
        print(f"  \033[1m\033[36mDELTA vs {prev_commit} ({mode})\033[0m")
        print("  " + "─" * $W)
        changes.sort(key=lambda x: -x[3])
        for name, c, p, pct in changes:
            arrow = "▲" if pct > 0 else "▼"
            if pct > 5:     color = "\033[32m"
            elif pct < -5:  color = "\033[31m"
            else:           color = "\033[2m"
            print(f"  {name:<28s}  {p:>12,} → {c:>12,}  {color}{arrow} {pct:+.1f}%\033[0m")
        print("  " + "─" * $W)
    else:
        mode = "quick" if cur_cfg["rounds"] <= 1 else f"{cur_cfg['rounds']}r×{cur_cfg['duration']}s"
        print(f"")
        print(f"  \033[2mNo comparable previous run ({mode}) for delta\033[0m")
PYEOF

# ══════════════════════════════════════════════════════════════════════════
# FOOTER
# ══════════════════════════════════════════════════════════════════════════

ELAPSED=$(( $(date +%s) - START_EPOCH ))
N_RUNS=$(python3 -c "import json; print(len(json.load(open('$HISTORY_FILE'))))" 2>/dev/null || echo "?")

echo ""
echo "${B}┌──────────────────────────────────────────────────────────────────────────────────────────┐${R}"
echo "${B}│${R}                                                                                          ${B}│${R}"
printf "${B}│${R}   ${CG}✓${R} ${B}Complete${R} — %s cells × %s rounds in ${B}%dm%02ds${R}%-38s${B}│${R}\n" \
       "$TOTAL_CELLS" "$TOTAL_ROUNDS" "$((ELAPSED/60))" "$((ELAPSED%60))" ""
echo "${B}│${R}                                                                                          ${B}│${R}"
printf "${B}│${R}   History    %-74s${B}│${R}\n" "$HISTORY_FILE"
printf "${B}│${R}   Runs       %-74s${B}│${R}\n" "$N_RUNS archived"
echo "${B}│${R}                                                                                          ${B}│${R}"
echo "${B}└──────────────────────────────────────────────────────────────────────────────────────────┘${R}"
echo ""
