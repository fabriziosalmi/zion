#!/usr/bin/env bash
# Verdict for a stability-soak run: reads the sampled RSS / fd / config-generation
# series and decides whether the process is bounded or leaking.
#
#   analyze.sh <samples.tsv> <gen0> <gen1>
#
# Split out of run.sh so the verdict can be tested on its own (analyze-selftest.sh
# feeds it a flat-but-noisy series, a real fd staircase and a real RSS climb and
# checks the exit code), without running a 3-minute soak.
#
# Exit 0 = bounded, 1 = leak / bad run. Knobs (same names as run.sh):
#   WARMUP RSS_BUDGET_BPS RSS_BUDGET_PCT FD_MARGIN FD_DRIFT FD_SIGMA RELOADS
set -euo pipefail
SAMPLES="${1:?usage: analyze.sh <samples.tsv> <gen0> <gen1>}"; gen0="${2:?}"; gen1="${3:?}"
WARMUP="${WARMUP:-20}"; RELOADS="${RELOADS:-40}"
RSS_BUDGET_BPS="${RSS_BUDGET_BPS:-600}"; RSS_BUDGET_PCT="${RSS_BUDGET_PCT:-10}"
FD_MARGIN="${FD_MARGIN:-40}"; FD_DRIFT="${FD_DRIFT:-3}"; FD_SIGMA="${FD_SIGMA:-5}"

awk -v warmup="$WARMUP" -v budget_bps="$RSS_BUDGET_BPS" -v budget_pct="$RSS_BUDGET_PCT" \
    -v fd_margin="$FD_MARGIN" -v fd_drift="$FD_DRIFT" -v fd_sigma="$FD_SIGMA" -v gen0="$gen0" -v gen1="$gen1" -v reloads="$RELOADS" '
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
    # fd stats: first-half vs second-half MEAN drift. Half-means rather than
    # 2-sample deciles, so the per-sample in-flight-connection jitter averages
    # out: a real socket leak is a monotonic staircase whose second-half mean
    # sits clearly above the first-half, while a bounded band has matching
    # halves within noise. A 2-sample decile was noise-dominated on the short
    # gate and flagged phantom drift.
    h=int(n/2); if (h<1) h=1
    for(i=1;i<=h;i++){ ff+=Yf[i] } ff/=h
    for(i=h+1;i<=n;i++){ fl+=Yf[i] } fl/=(n-h)
    fd_range = fmax - fmin; fd_dr = fl - ff
    # How large a half-drift is still NOISE? The fd count is the number of
    # in-flight connections, so it jitters by a dozen between samples and the
    # half-means differ by chance: measured over repeated identical runs the
    # half-drift had sd ~1.9 fds, so a fixed limit of 3 failed a healthy build
    # about one run in ten. Estimate the noise from THIS run instead: the residual
    # spread around the fitted fd trend (a leak is a trend, so it does not inflate
    # the noise estimate), scaled to the standard error of a half-mean difference
    # and inflated 1.5x for the sample-to-sample correlation of the series.
    Fx=0;Fy=0;Fxx=0;Fxy=0;Fyy=0
    for(i=1;i<=n;i++){Fx+=X[i];Fy+=Yf[i];Fxx+=X[i]*X[i];Fxy+=X[i]*Yf[i];Fyy+=Yf[i]*Yf[i]}
    Fxxc=Fxx-Fx*Fx/n; Fxyc=Fxy-Fx*Fy/n; Fyyc=Fyy-Fy*Fy/n
    fm=(Fxxc>0)?Fxyc/Fxxc:0; Fres=Fyyc-fm*Fxyc; if(Fres<0)Fres=0
    fres_sd=(n>2)?sqrt(Fres/(n-2)):0
    fd_noise = 1.5*fres_sd*sqrt(1.0/h + 1.0/(n-h))
    fd_limit = fd_sigma*fd_noise; if (fd_limit < fd_drift) fd_limit = fd_drift

    printf "  samples (post-warmup): %d over %ds (tail %d)\n", n, (X[n]-X[1]), nt
    printf "  RSS: mean %.1f MiB | overall slope %.1f B/s (%.2f%%/24h) | tail slope %.1f B/s (3-sigma %.1f, %.2f%%/24h) | tail/overall %.2f\n", \
        med/1048576.0, m, pct, mt, 3*se_mt, pctt, ratio
    printf "  fd : min %d, max %d, range %d, half-drift %.1f (limit %.1f = max(%d, %.0f x noise %.2f))\n", fmin, fmax, fd_range, fd_dr, fd_limit, fd_drift, fd_sigma, fd_noise
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
    if (fd_dr > fd_limit)     { printf "  FD half-drift %.1f exceeds %.1f (fd staircase = leaked sockets)\n", fd_dr, fd_limit; fail=1 }
    if ((gen1-gen0) < reloads/2) { printf "  only %d swaps observed (< %d); reloads did not run under load\n", gen1-gen0, reloads/2; fail=1 }
    exit fail
}
' "$SAMPLES"
