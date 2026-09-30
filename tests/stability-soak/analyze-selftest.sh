#!/usr/bin/env bash
# Self-test of the soak verdict (analyze.sh), in seconds and without a soak.
#
# The fast gate's pass/fail comes from a statistic over ~27 noisy samples; if that
# statistic is tighter than the noise the gate flakes, if it is looser than a real
# leak it is worthless. This pins both ends:
#
#   * the fixtures are six REAL healthy runs (180 s gate settings, 45 s warm-up,
#     40 reloads) and every one must pass;
#   * a socket leak of one fd per reload, injected into those same real series, must
#     FAIL (all six);
#   * a sustained RSS climb must FAIL, and too few reloads must FAIL.
#
# The 3-minute gate's resolution: measured by injecting leaks into the real series, it
# catches 0.22 fd/s (one per reload) 6 times in 6, 0.18 fd/s 5 in 6, 0.15 fd/s 3 in 6
# and 0.12 fd/s 1 in 6. A slower leak is buried in the in-flight-connection noise of so
# short a window (sd ~3 fds between samples). The 2-hour nightly, whose half-means are
# far tighter, is the verdict for slow leaks. The price of the old fixed limit of 3 was
# a healthy build failing about one run in ten.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
A="$HERE/analyze.sh"
export WARMUP=45 RSS_BUDGET_BPS=150000 RELOADS=40
fail=0
ok()  { printf '  ok    %s\n' "$*"; }
bad() { printf '  FAIL  %s\n' "$*"; fail=1; }

expect() { # expect <pass|fail> <label> <samples> [gen0 gen1]
    local want="$1" label="$2" f="$3" g0="${4:-0}" g1="${5:-40}" rc=0
    "$A" "$f" "$g0" "$g1" >/dev/null 2>&1 || rc=$?
    if [ "$want" = pass ] && [ "$rc" -eq 0 ]; then ok "$label passes"
    elif [ "$want" = fail ] && [ "$rc" -ne 0 ]; then ok "$label is refused"
    else bad "$label: expected $want, exit $rc"; fi
}

for f in "$HERE"/fixtures/healthy-*.tsv; do expect pass "healthy $(basename "$f")" "$f"; done

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
inject() { # inject <fd_per_s> <rss_bytes_per_s> <in> <out>: add a linear climb after warm-up
    python3 - "$@" <<'PY'
import sys
fd_rate, rss_rate, src, dst = float(sys.argv[1]), float(sys.argv[2]), sys.argv[3], sys.argv[4]
rows = [l.rstrip("\n").split("\t") for l in open(src)]
out = ["\t".join(rows[0])]
for r in rows[1:]:
    t = int(r[0]); extra = max(0, t - 45)
    out.append("\t".join([r[0], str(int(float(r[1]) + rss_rate * extra)), str(int(round(float(r[2]) + fd_rate * extra))), r[3]]))
open(dst, "w").write("\n".join(out) + "\n")
PY
}
for f in "$HERE"/fixtures/healthy-*.tsv; do
    n="$(basename "$f" .tsv)"
    inject 0.22 0 "$f" "$tmp/$n-leak1.tsv"; expect fail "$n + 1 fd leaked per reload" "$tmp/$n-leak1.tsv"
done
f="$HERE/fixtures/healthy-1.tsv"
inject 0 300000 "$f" "$tmp/rss.tsv"; expect fail "healthy-1 + sustained 300 KB/s RSS climb" "$tmp/rss.tsv"
expect fail "healthy-1 with only 3 reloads observed" "$f" 0 3

[ "$fail" -eq 0 ] && echo "analyze-selftest: all cases behave" || { echo "analyze-selftest: FAILED"; exit 1; }
