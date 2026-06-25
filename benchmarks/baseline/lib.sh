# shellcheck shell=bash
# =============================================================================
# Shared helpers for the Zion baseline harness (sourced by run-baseline.sh).
# Kept separate so the orchestrator stays readable and the parsing/stat logic
# is unit-testable in isolation.
# =============================================================================

log()  { printf '\033[1;36m▶ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }
skip() { printf '\033[1;35m∅ SKIP: %s\033[0m\n' "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

# Sample whole-process CPU% (sum across threads; can exceed 100% on multicore)
# and peak RSS(MB) of $pid over a $dur-second window; write "cpu_pct rss_mb" to $out.
#
# Linux: delta of (utime+stime) from /proc/$pid/stat over the window — the
#        accurate load-window figure. (`ps %cpu` on Linux is the LIFETIME average,
#        which would understate CPU during a short benchmark window.)
# macOS: ps %cpu sampled (lifetime-avg caveat; macOS is the smoke target only).
sample_proc() {
  local pid="$1" dur="$2" out="$3"
  if [ -r "/proc/$pid/stat" ]; then
    local clk; clk=$(getconf CLK_TCK 2>/dev/null || echo 100)
    local t0 t1
    t0=$(awk '{print $14+$15}' "/proc/$pid/stat" 2>/dev/null || echo 0)
    sleep "$dur"
    t1=$(awk '{print $14+$15}' "/proc/$pid/stat" 2>/dev/null || echo "$t0")
    local rss_kb; rss_kb=$(awk '/^VmHWM:/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)
    awk -v d=$((t1 - t0)) -v clk="$clk" -v w="$dur" -v r="$rss_kb" \
      'BEGIN{printf "%.1f %.1f\n", (w>0)?100*(d/clk)/w:0, r/1024}' > "$out"
  else
    local n=0 cpu_sum=0 rss_max=0 cpu rss
    for _ in $(seq 1 "$dur"); do
      read -r cpu rss < <(ps -o %cpu=,rss= -p "$pid" 2>/dev/null)
      [ -z "${cpu:-}" ] && break
      cpu_sum=$(awk -v a="$cpu_sum" -v b="$cpu" 'BEGIN{print a+b}')
      [ "${rss:-0}" -gt "$rss_max" ] && rss_max="$rss"
      n=$((n+1)); sleep 1
    done
    awk -v s="$cpu_sum" -v n="$n" -v k="$rss_max" \
      'BEGIN{printf "%.1f %.1f\n", (n>0)?s/n:0, k/1024}' > "$out"
  fi
}
