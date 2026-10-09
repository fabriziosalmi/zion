#!/usr/bin/env bash
# Produce the release report for one git ref, on the dedicated benchmark host, and bring the
# PDF back. One command per release:
#
#     benchmarks/report/report.sh v0.11.0              # full run, about an hour
#     benchmarks/report/report.sh v0.11.0 --prev v0.10.0
#     benchmarks/report/report.sh HEAD --quick         # 2 s trials: checks the pipeline, measures nothing
#
# What it does: ships this tree's harness and `git archive REF` to the host, builds REF with
# the release feature set (`--features dist`, what the published binaries use), runs the
# benchmark, the HTTP conformance suite and the external suites there, renders the PDF there
# (pinned WeasyPrint and matplotlib: the same JSON gives the same bytes), and copies
# everything to benchmarks/report/reports/<REF>/. The host must be idle: nothing else may run
# on it while this does. Provision it once with provision.sh.
#
# Environment: BOX (default ci@192.168.0.131).
# shellcheck disable=SC2029  # $RUN and friends are meant to expand on this side
set -euo pipefail

BOX="${BOX:-ci@192.168.0.131}"
REF="${1:?usage: report.sh REF [--prev REF] [--quick]}"
shift
PREV="" ; QUICK=""
while [ $# -gt 0 ]; do
  case "$1" in
    --prev) PREV="$2"; shift 2;;
    --quick) QUICK="--quick"; shift;;
    *) echo "unknown argument $1" >&2; exit 2;;
  esac
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
cd "$REPO"
SHA="$(git rev-parse "$REF^{commit}")"
SHORT="${SHA:0:7}"
SAFE="$(echo "$REF" | tr '/' '_')"
LABEL="$REF ($SHORT)"
OUT="$HERE/reports/$SAFE"
RUN="zion-report-$SAFE"                       # a directory per ref on the host

if [ -z "$PREV" ]; then
  # the report just before this ref in version order, if there is one
  shopt -s nullglob
  names=("$SAFE"); for d in "$HERE"/reports/*/; do names+=("$(basename "$d")"); done
  PREV="$(printf '%s\n' "${names[@]}" | sort -Vu | awk -v s="$SAFE" '$0 == s { print p; exit } { p = $0 }')"
  shopt -u nullglob
fi

echo "▶ ref $REF = $SHA"
echo "▶ shipping harness and source to $BOX:~/$RUN"
ssh "$BOX" "rm -rf ~/$RUN && mkdir -p ~/$RUN/harness/benchmarks ~/$RUN/src ~/$RUN/out"
rsync -a --delete --exclude reports --exclude __pycache__ "$HERE/" "$BOX:$RUN/harness/benchmarks/report/"
rsync -a --delete --exclude __pycache__ "$REPO/benchmarks/regress/" "$BOX:$RUN/harness/benchmarks/regress/"
git archive "$SHA" | ssh "$BOX" "tar -x -C ~/$RUN/src"
if [ -n "$PREV" ] && [ -d "$HERE/reports/$PREV" ]; then
  rsync -a "$HERE/reports/$PREV/result.json" "$BOX:$RUN/prev.json"
fi

echo "▶ building (release, --features dist)"
ssh "$BOX" ". ~/.cargo/env && cd ~/$RUN/src && cargo build --release --locked --features dist 2>&1 | tail -2"

echo "▶ measuring and testing on the host (do not touch it)"
ssh "$BOX" "set -e; export PATH=/opt/zion-bench/bin:\$PATH; cd ~/$RUN/harness/benchmarks/report
  BIN=~/$RUN/src/target/release/zion
  python3 bench.py --zion \$BIN --out ~/$RUN/out --label '$LABEL' $QUICK 2>&1 | tee ~/$RUN/out/bench.log
  python3 conformance.py --zion \$BIN --out ~/$RUN/out 2>&1 | tee ~/$RUN/out/conformance.log
  python3 external.py --zion \$BIN --out ~/$RUN/out 2>&1 | tee ~/$RUN/out/external.log"

echo "▶ rendering"
PREVARG=""; [ -n "$PREV" ] && [ -d "$HERE/reports/$PREV" ] && PREVARG="--prev ~/$RUN/prevdir"
ssh "$BOX" "set -e; cd ~/$RUN/harness/benchmarks/report
  if [ -f ~/$RUN/prev.json ]; then mkdir -p ~/$RUN/prevdir && cp ~/$RUN/prev.json ~/$RUN/prevdir/result.json; fi
  /opt/zion-bench/venv/bin/python render.py ~/$RUN/out --out ~/$RUN/out/zion-$SAFE-report.pdf $PREVARG"

mkdir -p "$OUT"
rsync -a "$BOX:$RUN/out/" "$OUT/"
rm -f "$OUT"/*.html "$OUT"/h2spec-*.xml "$OUT"/cachetests-*.json
echo "✔ $OUT/zion-$SAFE-report.pdf"
