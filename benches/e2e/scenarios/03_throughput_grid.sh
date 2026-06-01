#!/usr/bin/env bash
# S3 — keep-alive throughput ceiling across the payload x concurrency grid.
# Mac-orchestrated: runs wrk on the attacker, snapshots Prometheus deltas +
# SUT CPU around each run. TLS handshake AMORTIZED (keep-alive) so this
# isolates request-processing + proxy cost. Headline RPS table.
#
# wrk latency here is SERVICE-time (closed-loop) and is NOT cited for the paper
# tails — S5 (vegeta, open-loop) is the authoritative latency source.
#
# Usage: source env.sh; source lib/orchestrate.sh; ./03_throughput_grid.sh <run_dir> [dur] [reps]
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
source "$HERE/env.sh"; source "$HERE/lib/orchestrate.sh"
RUN_DIR="${1:-$RESULTS_ROOT/run_manual}"; DUR="${2:-20}"; REPS_M="${3:-2}"
PAYS=("/" "/1k.bin" "/10k.bin" "/100k.bin"); CONC=(100 200)
mkdir -p "$RUN_DIR/s3"
printf '%-10s %-5s %-4s %12s %10s %10s %8s %8s\n' payload conc rep "req/s" "p99(ms)" "RSS(MB)" zion%cpu atk_idle | tee "$RUN_DIR/s3/grid.txt"

for p in "${PAYS[@]}"; do
  for c in "${CONC[@]}"; do
    # 1 warmup (discarded) + REPS_M measured
    for rep in $(seq 0 "$REPS_M"); do
      tag="s3_$(echo "$p" | tr -d /)_c${c}_r${rep}"; [ "$p" = "/" ] && tag="s3_root_c${c}_r${rep}"
      T0=$(date +%s)
      sidecar=$(sut_cpu_sidecar_start "$((DUR+3))" "$tag")
      out=$(atk_exec "taskset -c $ATK_CORES wrk -t4 -c$c -d${DUR}s --latency -H 'Connection: keep-alive' https://$SUT_FQDN$p" 2>&1)
      T1=$(date +%s)
      rps=$(echo "$out" | awk '/Requests\/sec/{print $2}')
      p99=$(echo "$out" | awk '/^ *99%/{print $2}' | head -1)
      non2xx=$(echo "$out" | awk '/Non-2xx/{print $NF}')
      rss=$(python3 -c "print(round($(prom_query zion_process_resident_memory_bytes)/1048576,1))" 2>/dev/null)
      zcpu=$(ssh "$NODE1_HOST" "pct exec $SUT_CTID -- cat /tmp/${tag}.zion_cpu.log" 2>/dev/null | awk '/Average/{print $8}')
      aidle=$(echo "$out" | grep -q . && echo "$out" | awk '/Requests\/sec/{print "n/a"}')  # placeholder; mpstat below
      [ "$rep" = 0 ] && note="(warmup)" || note=""
      printf '%-10s %-5s %-4s %12s %10s %10s %8s %8s %s\n' "$p" "$c" "$rep" "${rps:-ERR}" "${p99:-?}" "${rss:-?}" "${zcpu:-?}" "${aidle:-?}" "$note" | tee -a "$RUN_DIR/s3/grid.txt"
      echo "$out" > "$RUN_DIR/s3/${tag}.wrk.txt"
      sleep "$COOLDOWN_S"
    done
  done
done
echo "S3 done -> $RUN_DIR/s3/grid.txt"
