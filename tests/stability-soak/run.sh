#!/usr/bin/env bash
# Stability soak — prove RSS and open FDs stay FLAT under stress (no leak).
# (Production-hardening item #4.)
#
# A front door runs for weeks; a per-request or per-reload leak that's
# invisible in a unit test becomes an OOM or an fd-exhaustion page in
# production. This drives a real Zion with the traffic shapes that exercise
# every leak-prone surface the leak-surface investigation named, samples
# zion_process_resident_memory_bytes + zion_process_open_fds over time, and
# fails if the steady-state RSS slope is a real, budget-breaking climb or the
# fd count grows without bound.
#
# The generators (each mapped to a surface):
#   G1  high-cardinality load — random Host + path + X-Forwarded-For per
#       request, POST body to a WAF route; each curl is a fresh TLS connection.
#       → route cache (LRU), response cache (evict), WAF scan, rate map (per
#         resolved-IP), and connection/fd churn.
#   G3  bad-TLS / RST churn → the handshake-error drop path.
#   G6  A/B reload rotation under load — rewrite zion.toml between two bodies
#       (different upstream set + route shape) and POST /admin/reload, many
#       times → the ArcSwap snapshot (router + health map) alloc/free lifecycle.
#
# LINUX ONLY: the RSS/FD gauges are read from /proc and are 0 on macOS/Windows
# (metrics.rs sample_resource_gauges is #[cfg(target_os="linux")]). On a dev
# Mac, run it in a Linux container (see tests/stability-soak/README.md). The
# harness hard-fails if the gauges read 0 (not Linux, or /proc is masked).
#
# Env knobs (PR gate uses short values; the nightly uses long ones):
#   DURATION (s, default 120)   total run
#   WARMUP   (s, default 20)    excluded from the slope fit (RSS ramps as caches
#                               and pools fill — that is bounded, not a leak)
#   INTERVAL (s, default 5)     sample cadence (gauges refresh at most 1 Hz)
#   WORKERS  (default 20)       G1 concurrent load workers
#   RELOADS  (default 40)       G6 config swaps across the run
#   CARDINALITY (default 20000) distinct Host/path/XFF values
#   MAX_ENTRIES (default 2000)  response-cache cap (MUST be > 0, else no evict)
#   RATE_LIMIT_RPS (default 200) MUST be > 0, else the rate map stays empty
#   RSS_BUDGET_BPS (default 600) steady-state RSS slope budget, bytes/sec
#   RSS_BUDGET_PCT (default 10)  and 24h-extrapolated growth < PCT% of steady
#   FD_MARGIN (default 40)      allowed fd range under concurrency
#   FD_DRIFT  (default 3)       allowed last-decile − first-decile fd drift
#   ZION_BIN / BACKEND_BIN      prebuilt binaries (CI/container builds them once)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DURATION="${DURATION:-120}"; WARMUP="${WARMUP:-20}"; INTERVAL="${INTERVAL:-5}"
WORKERS="${WORKERS:-20}"; RELOADS="${RELOADS:-40}"; CARDINALITY="${CARDINALITY:-20000}"
MAX_ENTRIES="${MAX_ENTRIES:-2000}"; RATE_LIMIT_RPS="${RATE_LIMIT_RPS:-200}"
RSS_BUDGET_BPS="${RSS_BUDGET_BPS:-600}"; RSS_BUDGET_PCT="${RSS_BUDGET_PCT:-10}"
FD_MARGIN="${FD_MARGIN:-40}"; FD_DRIFT="${FD_DRIFT:-3}"
HTTPS_PORT=4433; ADMIN_PORT=9180; BACKEND_PORT=9090
[ "$MAX_ENTRIES" -gt 0 ] || { echo "MAX_ENTRIES must be > 0 (else the cache never evicts)"; exit 2; }
[ "$RATE_LIMIT_RPS" -gt 0 ] || { echo "RATE_LIMIT_RPS must be > 0 (else the rate map stays empty)"; exit 2; }

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    G=$'\033[32m'; R=$'\033[31m'; B=$'\033[1m'; N=$'\033[0m'
else G=""; R=""; B=""; N=""; fi
step() { printf '\n%s── %s%s\n' "$B" "$*" "$N"; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/zion-soak.XXXXXX")"
STOP="$WORK/stop"
cleanup() {
    touch "$STOP" 2>/dev/null || true
    [ -f "$WORK/zion.pid" ] && kill "$(cat "$WORK/zion.pid")" 2>/dev/null || true
    [ -f "$WORK/be.pid" ] && kill "$(cat "$WORK/be.pid")" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

ZION_BIN="${ZION_BIN:-$ROOT/target/release/zion}"
BACKEND_BIN="${BACKEND_BIN:-$ROOT/benchmarks/backend/target/release/zion-bench-backend}"
[ -x "$ZION_BIN" ] || { step "building zion (release)"; (cd "$ROOT" && cargo build --release --bin zion); }
[ -x "$BACKEND_BIN" ] || { step "building bench backend"; (cd "$ROOT" && cargo build --release --manifest-path benchmarks/backend/Cargo.toml); }

step "self-signed cert"
( cd "$ROOT/benchmarks/certs" && bash generate.sh >/dev/null 2>&1 || true )
CERT="$ROOT/benchmarks/certs/tls.crt"; KEY="$ROOT/benchmarks/certs/tls.key"
[ -f "$CERT" ] && [ -f "$KEY" ] || { echo "cert generation failed"; exit 1; }

# Two config bodies A/B differing in upstream set + route shape, so each reload
# reallocates a genuinely different router + health map (not a no-op re-read).
write_config() { # $1 = variant (a|b)
    local extra_up="" extra_route=""
    if [ "$1" = b ]; then
        extra_up=$'\n[upstream.alt]\nurl = "http://127.0.0.1:'"$BACKEND_PORT"$'"'
        extra_route=$'\n[[route]]\npath = "/alt/{*rest}"\nupstream = "alt"'
    fi
    cat > "$WORK/zion.toml" <<EOF
[server]
listen_http     = "0.0.0.0:8080"
listen_https    = "0.0.0.0:$HTTPS_PORT"
xff_mode        = "rewrite"
trusted_proxies = ["127.0.0.1"]
rate_limit_rps  = $RATE_LIMIT_RPS

[tls]
cert_path  = "$CERT"
key_path   = "$KEY"
hot_reload = false

[upstreams]
backend = "http://127.0.0.1:$BACKEND_PORT"

[admin]
listen         = "127.0.0.1:$ADMIN_PORT"
auth           = "internal-ip"
rate_limit_rps = 500

[cache_profile.hot]
mode        = "memory"
max_entries = $MAX_ENTRIES
ttl_seconds = 60

[[route]]
path     = "/api/{*rest}"
upstream = "backend"
waf      = true

[[route]]
path          = "/cached/{*rest}"
upstream      = "backend"
cache_profile = "hot"$extra_up$extra_route

[[route]]
path     = "/{*rest}"
upstream = "backend"
EOF
}
write_config a

step "starting bench backend + zion (soak: ${DURATION}s, warmup ${WARMUP}s, $WORKERS workers, $RELOADS reloads, cardinality $CARDINALITY)"
"$BACKEND_BIN" > "$WORK/backend.log" 2>&1 & echo $! > "$WORK/be.pid"; disown
ZION_CONFIG="$WORK/zion.toml" "$ZION_BIN" > "$WORK/zion.log" 2>&1 & echo $! > "$WORK/zion.pid"; disown

metrics="https://127.0.0.1:$HTTPS_PORT/metrics"
# Trailing `|| true` is load-bearing: under `set -euo pipefail`, a transient
# curl failure (a reload in flight, or a reset from the g3 bad-TLS churn) makes
# this pipeline exit non-zero, and an assignment like `rss="$(val ...)"` in the
# sampler would then propagate that status and trip `set -e` — killing the MAIN
# shell mid-run, which fires the EXIT trap → cleanup() → `rm -rf $WORK`, and the
# still-running g6 generator dies with "zion.toml: No such file". Swallow it so
# `val` always succeeds and returns "" on failure (callers default with :-0).
val() { curl -sk -m 3 "$metrics" 2>/dev/null | awk -v k="$1" '$1==k{print $2; exit}' || true; }
for i in $(seq 1 30); do
    [ "$(curl -sk -o /dev/null -w '%{http_code}' -m 2 "https://127.0.0.1:$HTTPS_PORT/api/v1/data" 2>/dev/null || echo 000)" = 200 ] && break
    [ "$i" = 30 ] && { echo "::error::zion not ready"; tail -20 "$WORK/zion.log" >&2; exit 1; }
    sleep 1
done

# Guard: the gauges must be real. On non-Linux or a masked /proc they read 0 and
# the soak would pass vacuously — hard-fail instead.
rss0="$(val zion_process_resident_memory_bytes)"; rss0="${rss0:-0}"
if [ "$rss0" -le 0 ] 2>/dev/null; then
    echo "::error::zion_process_resident_memory_bytes is 0 — not Linux, or /proc is masked. The soak can only measure on Linux with an unmasked /proc."
    exit 2
fi
gen0="$(val zion_config_generation)"; gen0="${gen0:-0}"

# ── Generators ──
# NB: each generator runs in a background subshell that INHERITS the EXIT trap.
# Every generator (and any nested subshell) resets it first — otherwise a
# short-lived inner subshell (e.g. g3's /dev/tcp probe) would fire cleanup on
# its own exit and nuke $WORK + kill the daemons mid-run.
rand() { echo $(( (RANDOM * 32768 + RANDOM) % CARDINALITY )); }
randip() { echo "$(( RANDOM % 223 + 1 )).$(( RANDOM % 256 )).$(( RANDOM % 256 )).$(( RANDOM % 256 ))"; }

# G1: high-cardinality load — fresh connection per request, random host/path/XFF,
# alternating cached vs WAF-POST routes.
g1() {
    trap - EXIT
    local body; body="$(head -c 4096 /dev/zero | tr '\0' 'x')"
    while [ ! -f "$STOP" ]; do
        local h p ip
        h="h$(rand).example.com"; p="/cached/k$(rand)"; ip="$(randip)"
        curl -sk -o /dev/null -m 5 -H "Host: $h" -H "X-Forwarded-For: $ip" \
            "https://127.0.0.1:$HTTPS_PORT$p" 2>/dev/null || true
        curl -sk -o /dev/null -m 5 -X POST -H "Host: $h" -H "X-Forwarded-For: $ip" \
            -H "Content-Type: application/json" --data "{\"q\":\"$body\"}" \
            "https://127.0.0.1:$HTTPS_PORT/api/v1/data" 2>/dev/null || true
    done
}
# G3: bad-TLS / RST churn — open the TLS port and close immediately.
g3() {
    trap - EXIT
    while [ ! -f "$STOP" ]; do
        curl -sk -o /dev/null -m 0.2 "https://127.0.0.1:$HTTPS_PORT/" 2>/dev/null || true
        { exec 3<>"/dev/tcp/127.0.0.1/$HTTPS_PORT" && printf 'GET / bad\r\n' >&3 && exec 3>&-; } 2>/dev/null || true
        sleep 0.05
    done
}
# G6: A/B reload rotation under load.
g6() {
    trap - EXIT
    local n=0 variant=a
    local interval; interval="$(awk "BEGIN{print ($DURATION-2)/$RELOADS}")"
    while [ "$n" -lt "$RELOADS" ] && [ ! -f "$STOP" ]; do
        if [ "$variant" = a ]; then write_config b; variant=b; else write_config a; variant=a; fi
        curl -s -o /dev/null -m 3 -X POST "http://127.0.0.1:$ADMIN_PORT/admin/reload" 2>/dev/null || true
        n=$((n+1)); sleep "$interval"
    done
}

step "load + reloads running; sampling RSS/fd every ${INTERVAL}s"
load_pids=()
for _ in $(seq 1 "$WORKERS"); do g1 & load_pids+=("$!"); done
g3 & load_pids+=("$!")
g6 & g6_pid="$!"

# ── Sampler ──
t0="$(date +%s)"; printf 't\trss\tfd\tgen\n' > "$WORK/samples.tsv"
end=$(( t0 + DURATION ))
while [ "$(date +%s)" -lt "$end" ]; do
    now="$(date +%s)"; rss="$(val zion_process_resident_memory_bytes)"; fd="$(val zion_process_open_fds)"; gen="$(val zion_config_generation)"
    printf '%s\t%s\t%s\t%s\n' "$(( now - t0 ))" "${rss:-0}" "${fd:-0}" "${gen:-0}" >> "$WORK/samples.tsv"
    sleep "$INTERVAL"
done
touch "$STOP"; kill "${load_pids[@]}" "$g6_pid" 2>/dev/null || true
gen1="$(val zion_config_generation)"; gen1="${gen1:-0}"

# Copy samples out for CI artifact upload.
cp "$WORK/samples.tsv" "$ROOT/soak-samples.tsv" 2>/dev/null || true

# ── Raw samples: printed so the curve shape is visible in the CI log even on a
#    failure (the shape — ramp-then-plateau vs sustained climb — is what tells a
#    bounded working-set from a real leak; don't make a reader guess from a slope). ──
step "samples (t=s  rss=MiB  fd  gen)"
awk 'NR==1{next}{printf "    %5ds  %8.1f  %4d  %d\n", $1, $2/1048576, $3, $4}' "$WORK/samples.tsv"

# ── Analysis: RSS slope (post-warmup) with a ramp-vs-leak discriminator; fd bound. ──
# A BOUNDED process (caches fill, the mimalloc working-set settles, ArcSwap
# reload churn allocates+frees) RAMPS then PLATEAUS — its RSS slope DECELERATES.
# A genuine leak keeps climbing at a SUSTAINED slope. Fitting only the whole
# post-warmup window can't tell them apart (both show a positive slope), so we
# also fit the TAIL (last 60%) and flag a leak only when the tail slope is
# significant, over budget, AND still ~as steep as the overall slope
# (tail/overall >= 0.5 — i.e. still climbing at the end, not settling).
step "analysis"
awk -v warmup="$WARMUP" -v budget_bps="$RSS_BUDGET_BPS" -v budget_pct="$RSS_BUDGET_PCT" \
    -v fd_margin="$FD_MARGIN" -v fd_drift="$FD_DRIFT" -v gen0="$gen0" -v gen1="$gen1" -v reloads="$RELOADS" '
NR==1 { next }                                   # header
{
    t=$1; rss=$2; fd=$3
    if (t < warmup) next                          # exclude the warm-up ramp
    n++; X[n]=t; Yr[n]=rss; Yf[n]=fd
    if (fd>fmax||fmax==0) fmax=fd
    if (fmin==0||fd<fmin) fmin=fd
}
END {
    if (n < 8) { printf "  FAIL — only %d post-warmup samples (need >=8); soak too short\n", n; exit 1 }
    # overall least-squares slope over [1..n]
    Sx=0;Sy=0;Sxx=0;Sxy=0;Syy=0
    for(i=1;i<=n;i++){Sx+=X[i];Sy+=Yr[i];Sxx+=X[i]*X[i];Sxy+=X[i]*Yr[i];Syy+=Yr[i]*Yr[i]}
    Sxxc=Sxx-Sx*Sx/n; Sxyc=Sxy-Sx*Sy/n; Syyc=Syy-Sy*Sy/n
    m=Sxyc/Sxxc; Se2=Syyc-m*Sxyc; vm=(Se2/(n-2))/Sxxc; if(vm<0)vm=0; se_m=sqrt(vm)
    med=Sy/n; pct=(med>0)?100.0*m*86400.0/med:0
    # tail least-squares slope over [ts..n] = last 60% of post-warmup samples
    ts=int(n*0.4)+1; if(ts<1)ts=1; nt=n-ts+1
    Tx=0;Ty=0;Txx=0;Txy=0;Tyy=0
    for(i=ts;i<=n;i++){Tx+=X[i];Ty+=Yr[i];Txx+=X[i]*X[i];Txy+=X[i]*Yr[i];Tyy+=Yr[i]*Yr[i]}
    Txxc=Txx-Tx*Tx/nt; Txyc=Txy-Tx*Ty/nt; Tyyc=Tyy-Ty*Ty/nt
    mt=Txyc/Txxc; TSe2=Tyyc-mt*Txyc; vmt=(nt>2)?(TSe2/(nt-2))/Txxc:0; if(vmt<0)vmt=0; se_mt=sqrt(vmt)
    medt=Ty/nt; pctt=(medt>0)?100.0*mt*86400.0/medt:0
    ratio=(m>0)?mt/m:0
    # fd stats: first-half vs second-half MEAN drift. Half-means (not 2-sample
    # deciles) so the per-sample in-flight-connection jitter averages out — a
    # real socket leak is a monotonic staircase (second-half mean clearly above
    # first-half), while a bounded band's halves match within noise. (A decile
    # was noise-dominated on the short fast gate and flagged phantom drift.)
    h=int(n/2); if (h<1) h=1
    for(i=1;i<=h;i++){ ff+=Yf[i] } ff/=h
    for(i=h+1;i<=n;i++){ fl+=Yf[i] } fl/=(n-h)
    fd_range = fmax - fmin; fd_dr = fl - ff

    printf "  samples (post-warmup): %d over %ds (tail %d)\n", n, (X[n]-X[1]), nt
    printf "  RSS: mean %.1f MiB | overall slope %.1f B/s (%.2f%%/24h) | tail slope %.1f B/s (3-sigma %.1f, %.2f%%/24h) | tail/overall %.2f\n", \
        med/1048576.0, m, pct, mt, 3*se_mt, pctt, ratio
    printf "  fd : min %d, max %d, range %d, half-drift %.1f\n", fmin, fmax, fd_range, fd_dr
    printf "  reloads: generation %d -> %d (%d swaps under load)\n", gen0, gen1, gen1-gen0

    fail=0
    significant = (mt > 3*se_mt)                   # tail slope clearly above noise
    over_budget = (mt >= budget_bps) && (pctt >= budget_pct)
    sustained   = (ratio >= 0.5)                   # not decelerating toward a plateau
    if (significant && over_budget && sustained) {
        printf "  RSS LEAK: tail slope %.1f B/s is significant, over budget (>= %d B/s and >= %d%%/24h), and SUSTAINED (tail/overall %.2f >= 0.5 — still climbing at the end, not a bounded ramp)\n", mt, budget_bps, budget_pct, ratio
        fail=1
    }
    if (fd_range > fd_margin) { printf "  FD range %d exceeds margin %d (unbounded fd growth?)\n", fd_range, fd_margin; fail=1 }
    if (fd_dr > fd_drift)     { printf "  FD half-drift %.1f exceeds %d (fd staircase = leaked sockets)\n", fd_dr, fd_drift; fail=1 }
    if ((gen1-gen0) < reloads/2) { printf "  only %d swaps observed (< %d); reloads did not run under load\n", gen1-gen0, reloads/2; fail=1 }
    exit fail
}
' "$WORK/samples.tsv"
rc=$?

step "result"
if [ "$rc" -eq 0 ]; then
    echo "  ${G}${B}PASS${N} — RSS bounded (tail slope within budget or decelerating to a plateau); open fds bounded; leak surfaces stressed."
else
    echo "  ${R}${B}FAIL${N} — see the analysis above; samples at soak-samples.tsv"
fi
exit "$rc"
